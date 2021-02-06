---
title: "Shabak Challenge 2021: Python4"
date: 2021-02-06
summary: Still better than Python 2
---

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

- [Introduction](#introduction)
- [Python, you say?](#python-you-say)
- [Doesn't look like anything to me](#doesnt-look-like-anything-to-me)
- [Who mitigates the mitigations](#who-mitigates-the-mitigations)
- [Two of your finest string, please](#two-of-your-finest-string-please)
- [Seek, and ye shall find](#seek-and-ye-shall-find)
- [The gift that keeps on giving](#the-gift-that-keeps-on-giving)
- [Hop to it](#hop-to-it)
- [Into the forest I go](#into-the-forest-i-go)

## Introduction

The [challenge][Challenge] description reads:

> Welcome to 2021! We decided to follow tradition and start working on the next
> python version.
>
> Don't worry, we made sure no vulnerabilities are exploitable, using modern mitigation
> techniques.
>
> Have fun running your scripts!!

This is it, folks. This is the big one.

## Python, you say?

No, not really. Which is probably for the best, since we have less code to read.

What we have here is [yet][baby-risc] [another][paging] interpreter with a fairly
limited set of instructions:

- Control flow
  - `nop`
    - Prints `"Nope!"`.
  - `label <label_name>`
    - Sets a label in the code, what can be called or jumped to.
    - Execution begins at the `main` label.
  - `call <label>`
    - Calls the specified label with a fresh local variable context (see below).
  - `ret`
    - Returns from a `call` or from `main`.
    - The last instruction executed by a script must be `ret`. Otherwise,
      the interpreter terminates.
  - `jmp <label>`
    - Jumps to a given label.
  - `cbz <variable_name> <label>`
    - Jumps to the given label if the given variable is 0.
- Variables
  - `def <variable_name> <value>`
    - Defines a new variable with the given name and initializes it to the given value.
    - Terminates the interpreter if a variable with the same name already exists.
    - Value must be either a hex 64-bit integer (e.g. `0x1337`) or a string
      (e.g. `"Pasten"`).
  - `mov <dest> <src>`
    - Moves the contents of the `src` variable into `dest`.
  - `print <variable>`
    - Prints the contents of the given variable.
- "Arithmetic"
  - `add <dest> <var1> <var2>`
    - Stores in the `dest` variable the sum of `var1` and `var2`, which must be
      of the same type.
    - This instruction will be explored [later on](#two-of-your-finest-string-please).
  - `sub <dest> <var1> <var2>`
    - Stores in the `dest` variable the difference of `var1` and `var2`, which must be
      of the same type.
    - This instruction will be explored [later on](#hop-to-it).
- Registers
  - `load <var> <register>`
    - Stores in the variable the contents of the register.
    - The variable must be of integer type.
  - `store <register> <var>`
    - Stores in the register the contents of the variable.
    - The variable must be of integer type.

The interpreter reads a script from `stdin` and executes it. It continues to
read and execute scripts until either a script fails or the execution timeout
(60 seconds) is reached.

The interpreter has 10 64-bit integer registers, named `$0` to `$9`. These registers
are initialized to zero on startup and are shared among all scripts. That is,
they are not reset to zero for each new script. They are also preserved across
the `call` instruction.

The main function in the interpreter is `execute_interpreter_function`. For each script,
it is first called to begin execution at the `main` label. Each invocation of the `call`
instruction results in a call to this function, as well. This function also holds
the local variables for each script function.

![Spock & Number One, Star Trek: Discovery, "Fascinating."](https://media.giphy.com/media/TEEm7KGKMgbAfUE9VH/giphy.gif)

## Doesn't look like anything to me

Like in previous challenges, the flag is stored in a file called `flag` in the current
working directory. Unfortunately for us, the interpreter doesn't provide any
instructions for reading files or executing arbitrary commands. What's worse, all
the string manipulation instructions validate everything, so we can't overflow.
And there are no instructions that do anything even remotely nefarious.

But what's this? In the `init.c` file? Mayhaps we overlooked something?

```c++
/* Implemented in glibc */
int arch_prctl(int code, unsigned long * addr);

#define NO_SHADOW_STACK_ATTR __attribute__((no_sanitize("shadow-call-stack")))
#define CONSTRUCTOR_ATTR __attribute__((constructor))

__attribute__((aligned(16))) uint8_t SHADOW_STACK[4096] = {0};

CONSTRUCTOR_ATTR NO_SHADOW_STACK_ATTR void initiliaze_shadow_stack(void)
{
    // In clang's 'shadow-call-stack', the shadow stack is stored in 'gs'.
    arch_prctl(ARCH_SET_GS, (void *)SHADOW_STACK);
}
```

The `arch_prctl` function here sets the base address for the `GS` register to
the address of the `SHADOW_STACK` buffer.

Looking in the supplied `Makefile`, we can also see that the interpreter is compiled
with `-fsanitize=shadow-call-stack`. Let's see what the [documentation][shadow-stack]
has to say:

> ShadowCallStack is an **experimental** instrumentation pass, currently only
> implemented for x86_64 and aarch64, that protects programs against return address
> overwrites (e.g. stack buffer overflows.) It works by saving a function's return
> address to a separately allocated 'shadow call stack' in the function prolog and
> checking the return address on the stack against the shadow call stack in the
> function epilog.

Great, so even *if* we manage to overwrite the return address, we'll promptly crash.

Time to pack it in.

Nothing to see here.

![Leonard McCoy, Star Trek: Beyond, "Well that's just typical."](https://media.giphy.com/media/77PW0C7xUEsrC/giphy.gif)

## Who mitigates the mitigations

Alright, fine, let's throw the binary into Ghidra and see how this shadow stack
thingy works. After all, the README boasts of the modern mitigation techniques
used here.

Here's what the prologue looks like:

![Shadow stack function prologue](/img/python4-shadow-stack-prologue.png)

And the epilogue:

![Shadow stack function epilogue](/img/python4-shadow-stack-epilogue.png)

Based on this we can conclude that the shadow stack looks like this:

```c++
struct shadow_stack
{
    size_t offset;
    void * return_address[511];
};
```

Upon function entry, the return address is stored in the next available slot,
and just before returning the return address is compared to the saved one.
If a mismatch is detected - the program crashes.

However...

![Shadow stack is adjacent to interpreter registers](/img/python4-shadow-stack-regs.png)

The shadow stack is stored immediately before the register array! And since there is
no bounds checking on the shadow stack, if we recurse deeply enough we'll be able
to overwrite the return address by writing to the appropriate register.

And can we control the recursion from the Python4 script? Yes! Since every `call`
instruction results in another call to `execute_interpreter_function`.

![Michael Burnham, Star Trek: Discovery, "Hell yeah."](https://media.giphy.com/media/9uIStfgxoUj5wV8BGG/giphy.gif)

We are back in the game.

## Two of your finest string, please

All of this is still academic, since we can't overwrite the return address. Or can we?
Let's take another look at those string manipulation instructions.

The `def` instruction looks solid. It simply copies its operand to the local variable,
with bounds checking.

What about `add`? Here's the relevant code from the `exec_add` function:

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
{{< highlight "c++" "lineanchors=exec-add,anchorlinenos=true" >}}
interpreter_var_t * dest_var = find_var(script->local_vars, instruction->operands.add_operands.dest_var);
interpreter_var_t * op1_var = find_var(script->local_vars, instruction->operands.add_operands.op1_var);
interpreter_var_t * op2_var = find_var(script->local_vars, instruction->operands.add_operands.op2_var);
// ...
const char * op1_str = op1_var->var_value.var_value_string;
const char * op2_str = op2_var->var_value.var_value_string;
char * dest_str = dest_var->var_value.var_value_string;
dest_var->var_type = VAR_TYPE_STR;
if ((strlen(op1_str) + strlen(op2_str) + 1) > sizeof(dest_var->var_value.var_value_string))
{
    puts("String addition failed - size too long");
    return INSTRUCTION_EXEC_CMD_ERROR;
}
strncpy(dest_str, op1_str, sizeof(dest_var->var_value.var_value_string));
strncat(dest_str, op2_str, strlen(op2_str));
{{< /highlight >}}
<!-- markdownlint-restore -->

There is an overflow here. It's tricky to see, but it's there. And it is *beautiful*.

What happens if we do `add var1 var2 var1`? This should be equivalent to
`var1 = var2 + var1`, but is it really? First, at [line 14](#exec-add-14),
the code copies the contents of `var2` into `var1`. Then, at [line 15](#exec-add-15),
it copies the contents of `var1` into `var1`. But `var1` now contains the same
string that's in `var2`! So what we're really doing is `var1 = var2 + var2`.

Crucially, the bounds check at [line 9](#exec-add-9) misses this case. So if
`strlen(var2) + strlen(var1)` is smaller than the buffer size (because `var1` is empty,
for instance), but `2 * strlen(var2)` isn't, we're going to overflow.

![Agnes Jurati, Star Trek: Picard, "a work of art"](https://media.giphy.com/media/Z97RJsyc5wLEgw5pNN/giphy.gif)

That's all well and good, but is this overflow useful? Here's the stack layout
of the `execute_interpreter_function` function, where the local variables
reside:

![execute_interpreter_function stack setup](/img/python4-stack-setup.png)

![execute_interpreter_function stack layout](/img/python4-stack-layout.png)

And here's how the local variables are laid out:

```c++
#define VAR_NAME_MAX_LEN (16)
#define VAR_STR_VALUE_MAX_LEN (64)
#define LOCAL_VARS_AMOUNT (32)

typedef struct interpreter_var_s
{
    char var_name[VAR_NAME_MAX_LEN];
    interpreter_var_type_t var_type;
    union var_value_u
    {
        char var_value_string[VAR_STR_VALUE_MAX_LEN];
        int64_t var_value_int;
    } var_value;
} interpreter_var_t;

typedef struct interpreter_local_vars_s
{
    interpreter_var_t vars[LOCAL_VARS_AMOUNT];
} interpreter_local_vars_t;
```

It's math time! To overwrite the return address we have to write `64 + 6 * 8 + 8 == 120`
bytes:

- `64` to overwrite the local variable buffer (`VAR_STR_VALUE_MAX_LEN`).
- `6 * 8 == 48` to overwrite the saved registers.
- `8` for the return address.

Since our overflow technique writes a given string twice, we need a string of length
`60`, with the desired return address at the end.

There's just one problem.

Where do we go?

## Seek, and ye shall find

Since we have control of the return address, we'll need to employ some ROP magic.
There are several options for how to get a shell:

1. ["One gadget"][one-gadget].
2. [`ret2dlresolve`][ret2dlresolve].
3. [SROP][srop].
4. The good old [`ret2libc`][ret2libc].

We're going to use the classic method, because if it ain't broke - don't fix it[^1].
Specifically, we want to be able to call `system("/bin/sh")`. For that, we need to
do two things:

1. Place the parameter `"/bin/sh"` somewhere in memory.
2. Return to `system` using the buff-o we found.

The first part is kinda easy: since we can write arbitrary data to the interpreter
registers, we can use them for storage.

Unfortunately for us (again), there's ASLR. So really we have two new problems:

1. Find the address of the interpreter registers array in memory.
2. Find the address of `system`.

Let's deal with the first one. We can use the same trick as for patching the shadow
stack:

```plain
label main
    def reg 0x0
    def is_reg_zero 0x0
    def zero 0x0
    load reg $0
    sub is_reg_zero reg zero
    cbz is_reg_zero recurse
    print reg
    ret
label recurse
    call main
    ret
```

This script will recurse until the first time the shadow stack overflows into
the interpreter registers, and print that value.

Okay, but where does that point? Time to fire up GDB, set a breakpoint on `exec_print`,
and do some more math[^2].

***Quick sidenote**: since we'll be relying heavily on the layout of various binaries
in memory, we have to ensure we use the correct versions. The supplied `Dockerfile`
gives the image we have to use, and there is also a `libc` binary we have to place
inside.*

![GDB output of executable address leak](/img/python4-executable-leak.png)

![GDB offset of leaked address from executable base](/img/python4-executable-offset.png)

Looking in Ghidra, we can also see that this offset, `0x41F8`, points at
the address just after the call to `find_var` inside `exec_load`.

Things are looking up.

![Sam Rutherford, Star Trek: Lower Decks, "This is gonna be great!"](https://media.giphy.com/media/C0s0NQymqS3WMMWp72/giphy.gif)

## The gift that keeps on giving

Now for the tricky bit - leaking the base address of `libc`. Unfortunately,
none of the interpreter functions are used as callbacks in `libc`, so we can't
use the same trick with the shadow stack.

What *can* we do then? We can note that the buffer overflow we found can also
be used to leak information from the stack. Consider again the structure of a local
variable:

```c++
#define VAR_NAME_MAX_LEN (16)
#define VAR_STR_VALUE_MAX_LEN (64)

typedef struct interpreter_var_s
{
    char var_name[VAR_NAME_MAX_LEN];
    interpreter_var_type_t var_type;
    union var_value_u
    {
        char var_value_string[VAR_STR_VALUE_MAX_LEN];
        int64_t var_value_int;
    } var_value;
} interpreter_var_t;
```

And consider this:

1. Initially, the `var_type` field of all local variables is initialized to
   `VAR_TYPE_UNDEF` (so we can't directly read from them). However, the rest of
   the structure is not initialized (see the `initialize_local_vars` function
   in `interpreter.c`).
2. `VAR_TYPE_STR == 0`.
3. Our overflow writes a null-terminated string (with [`strncat`][strncat]).
4. We're exploiting a little-endian machine.

All this means that if we can overflow from one variable and into the next, we can
set the `var_type` of this next variable to `0`, by overwriting the first byte
of `var_type` with the null-terminator of the overflowing string. This will allow
us to read whatever happened to be on the stack!

Is this useful? It might be. If we call a complex function inside `libc`, it just
might leave some information on the stack that we can use to calculate the `libc`
base. Lucky for us, we can call `printf`:

```plain
label main
    def reg 0x4141414141414141
    print reg
    call leak
    ret
label leak
    ret
```

This will call `printf`, then immediately cause `execute_interpreter_function`
to be called again, which will allocate a boatload of local variables on the stack.
Hopefully, we'll be able to leak something interesting.

Once again, we fire up GDB and go hunting.

![Christopher Pike, Star Trek: Discovery, "Good luck out there, Captain"](https://media.giphy.com/media/Yqc7d8UoE5KdlQZgFV/giphy.gif)

Specifically, we set a breakpoint on `execute_interpreter_function` and dump
the stack[^3]:

![GDB execute_interpreter_function stack dump](/img/python4-stack-dump.png)

(The 352 here is the size of the local variables array divided by 8, the pointer size.)

pwndbg's coloring really helps here: we're looking for any addresses that are marked
as code (red) or data (pink). There are quite a few options to choose from, however
it appears that some of these addresses move around. That is, they do not appear at
the same stack location across different runs of the interpreter.

At offset `0xA10`, however, we find what we're looking for:

1. An address within the `libc` data section.
2. That doesn't move around on the stack across runs of the interpreter.
3. Is located at the beginning of the local variable data buffer, so we can easily read
   it via the `print` instruction.

Here's how we leak it:

```plain
label main
    def reg 0x4141414141414141
    print reg
    call leak
    ret
label leak
    def padding0 0x00
    def padding1 0x00
    def padding2 0x00
    def padding3 0x00
    def padding4 0x00
    def padding5 0x00
    def padding6 0x00
    def padding7 0x00
    def padding8 0x00
    def padding9 0x00
    def padding10 0x00
    def padding11 0x00
    def padding12 0x00
    def padding13 0x00
    def padding14 0x00
    def padding15 0x00
    def padding16 0x00
    def padding17 0x00
    def padding18 0x00
    def padding19 0x00
    def padding20 0x00
    def padding21 0x00
    def padding22 0x00
    def padding23 0x00
    def padding24 0x00
    def padding25 0x00
    def padding26 0x00
    def PATTERN "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    def OVERFLOW_HERE ""
    add OVERFLOW_HERE PATTERN OVERFLOW_HERE
    print AAAAAAAAAAAAAAAA
    ret
```

Notice how the name of the variable the script prints out is 16 characters-long,
even though the limit is 15 characters. The variable type, `VAR_TYPE_STR`, serves
as the null-terminator.

We're also relying on the fact that the address we're leaking has no null bytes
except the two most significant ones.

And the address we get is at offset `0x1ED560` from `libc` base:

![GDB offset of leaked address from libc base](/img/python4-libc-offset.png)

## Hop to it

We now have the base addresses of both the interpreter and of `libc`. Therefore, we can
calculate the addresses of the register array (where we'll place the `"/bin/sh"` string)
and of the `system` function.

All that remains is to build a ROP chain that will load the address of `"/bin/sh"` into
`RDI` and call `system`. A great way to do this is with [ROPgadget][ropgadget].
The tool presents many possible gadgets, but a particularly interesting one
is at offset `0x2544` in the interpreter:

```nasm
mov rdi, r15
lea rsi, [rsp + 0x40]
call [rbx]
```

Why is it interesting? Because [a long time ago](#two-of-your-finest-string-please)
we observed that `execute_interpreter_function` saves both the `RBX`
and the `R15` registers, and restores them before returning. So if, while overflowing
the stack, we also ensure that `R15` gets set with the address of `"/bin/sh"`
and `RBX` gets set with an address that holds a pointer to `system`, we're golden!

![Star Trek: Discovery, spore jump](https://media.giphy.com/media/BHJ8BRu1CgTjoDfvoo/giphy.gif)

There's just one tiny problem[^4]. All these addresses that we are supposed to write
to the stack have null bytes in them, and we're using `strncat`. We need to solve this
somehow.

Fortunately, the solution is right under our noses, in the implementation of
the `sub` instruction. When we do `sub var1 var2 var3`, where `var2` and `var3` are
both string variables, then if `var3` is a suffix of `var2`, `var1` will receive
`var2` without this suffix. For example:

```plain
def var1 0x0
def var2 "Pasten"
def var3 "en"
sub var1 var2 var3
print var1
```

Will print `"Past"`.

What happens if we do this instead?

```plain
def var1 "Pasten"
def var2 "en"
sub var1 var1 var2
print var1
```

The output will be the same, but more importantly the variable buffer for `var1`
will contains `"Past\0n"`. In essence, we replaced a single byte in the string
with a null byte.

The trick here is that this "subtraction" does no bounds checking on the buffers!
After all, we're operating on two valid string variables here, so there's
no chance subtraction of a suffix will cause an overflow 😉.

This means we can first overflow the stack with a buffer that has placeholders instead
of the null bytes, and then surgically implant nulls using subtraction. We'll just have
to start from the last null and move inwards.

## Into the forest I go

[Remember](#python-you-say) how the interpreter allows us to run multiple scripts
in one session? This means that we can run a script, parse its output, and modify
the next script we send accordingly. And, since it's the same process running
all those scripts, the addresses we leak will stay relevant.

So here's the plan:

1. Send a [script](#seek-and-ye-shall-find) to leak the executable's base address.
2. Send a [script](#the-gift-that-keeps-on-giving) to leak the `libc` base address.
3. Create a [script](#hop-to-it) that:
   1. Places `"/bin/sh"` into one of the interpreter registers.
   2. Places the address of `system` into another register.
   3. Overflows the stack so as to trigger a ROP gadget that will call `system`.
   4. [Patches](#who-mitigates-the-mitigations) the shadow stack with the address
      of the ROP gadget.
4. Send that script.
5. Send the `cat flag` command to the shell.

![Python4 flag retrieval](/img/python4-flag.png)

![Michael Burnham, Star Trek: Discovery, "YES!"](https://media.giphy.com/media/PnDRO1werTjHI7YSmc/giphy.gif)


[^1]: Actually, I've been informed by a knowledgeable third-party that the one-gadget
      method doesn't work for this challenge; the `ret2dlresolve` requires too much
      data to be placed in memory; and SROP requires a lot of data to be placed
      on the stack and we still have to leak an address in `libc` for it to work.
      All in all, the classic method is the "simplest".

[^2]: Alternatively, let [pwndbg][pwndbg] do all the hard work.

[^3]: The keen-eyed may notice that the dump begins at offset 8 from `RSP`.
      The explanation to this can be seen in the stack layout screenshot
      [above](#two-of-your-finest-string-please) 😎.

[^4]: Another one?! Surely you jest.


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://archive.org/download/shabak-challenge-2021/shabak-challenge-2021.zip/
    "Python4 challenge files"

[baby-risc]: {{< ref "/blog/baby-risc.md" >}}
    "Shabak Challenge 2021: BabyRISC"

[paging]: {{< ref "/blog/paging.md" >}}
    "Shabak Challenge 2021: Paging"

[shadow-stack]: https://releases.llvm.org/7.0.1/tools/clang/docs/ShadowCallStack.html
    "ShadowCallStack - Clang 7 documentation"

[one-gadget]: https://github.com/david942j/one_gadget
    "david942j/one_gadget: The best tool for finding one gadget RCE in libc.so.6"

[ret2dlresolve]: https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62
    "Return-to dl-resolve"

[srop]: https://en.wikipedia.org/wiki/Sigreturn-oriented_programming
    "Sigreturn-oriented programming - Wikipedia"

[ret2libc]: https://en.wikipedia.org/wiki/Return-to-libc_attack
    "Return-to-libc attack - Wikipedia"

[pwndbg]: https://github.com/pwndbg/pwndbg
    "pwndbg/pwndbg: Exploit Development and Reverse Engineering with GDB Made Easy"

[strncat]: https://en.cppreference.com/w/c/string/byte/strncat
    "strncat, strncat_s - cppreference.com"

[ropgadget]: https://github.com/JonathanSalwan/ROPgadget
    "JonathanSalwan/ROPgadget"
