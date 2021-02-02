---
title: "Shabak Challenge 2021: BabyRISC"
date: 2021-01-25T12:54:00+02:00
summary: Correct for specific values of zero
---

**Update 2021-01-31**: Archive moved to the [Internet Archive][Challenge].

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

## Introduction

The [challenge][Challenge] description reads:

> Following ARM's success, I went ahead and designed my own RISC assembly language.
>
> I wrote a simulator, so you'll be able to run your own programs and enjoy
> the (very) reduced instruction set!
>
> Of course, with such minimal implementation, reading the flag is impossible.

Since this is an pwn challenge, we're probably going to have to write some code
in this fictional RISC assembly in order to read the flag.

So, let's take a look.

## The C in RISC

A cursory examination of the source code reveals that the complete set of instructions
is listed in the `asm_instructions.h` file, and the implementation is inside the
corresponding `.c` file. And just to make our life a little more interesting,
the implementation is riddled with macros :)

We have the usual arithmetic operations (addition, multiplication, bit twiddling, etc.),
as well as some more interesting things:

- Output operations:
  - `PRINTC` to print the lower byte of a register as a character.
  - `PRINTDD` and `PRINTDX` to print the value of a register in decimal or hexadecimal
    formats, respectively.
  - `PRINTNL` to print a newline.
- Stack operations:
  - `PUSH` and `POP`.
  - `PUSHCTX` and `POPCTX`.
- Flow-control operations:
  - `RET`, to terminate execution unconditionally.
  - `RETNZ`, to terminate execution if the given register _is not_ zero.
  - `RETZ`, to terminate execution if the given register _is_ zero.

Speaking of registers, our fictional architecture has 9 of them, as defined in
`asm_processor_state.{c,h}`:

- `ZERO`
- `R0`-`R6`
- `SP`

Almost every arithmetic operation `OP` has two forms:

- The "regular" form, `<OP> <R>, <R>, <R>`, i.e. an opcode followed by
  3 register specifications.
- The "immediate" form, `<OPI> <R>, <R>, <IMM32>`, i.e. an opcode followed by
  2 register specifications, followed by an immediate value (32-bit).

For instance, `ADD R0, R1, R1` will calculate `R1 + R1` and store the result in `R0`.
Similarly, `ADDI R0, R1, 42` will calculate `R1 + 42` and store the result in `R0`.

Looking through the code, explicit writes to the `ZERO` register are forbidden
(enforced by the function `write_reg` in `asm_processor_state.c`). For instance,
we can't do `ADD ZERO, R0, R0`. That is, the `ZERO` register always contains the value
`0`.

Finally, the `SP` register is, unsurprisingly, the stack pointer. The processor has
a 4kB stack, and the instructions mentioned above are used to manipulate it.

## The Plan

Now that we understand the architecture, what do we actually have to do in order to
get the flag?

The flag itself is stored in a file called `flag` in the current directory. However,
the instructions provided by the simulator do not provide for reading files. Indeed,
they do not seem to be fit for any nefarious purpose! The print instructions do not use
any unsafe format strings, and all stack accesses are validated so as not to overflow.
Here goes out hope for RCE.

But do we actually have to execute arbitrary code? Perhaps it's time we took a look
at what the simulator actually does.

Looking in `main.c`, we notice that the simulator first generates some sort of
"admin code", then reads the user-supplied assembly from `stdin`, then executes
them: first the user code, then the admin code.

What's this admin code? First, it checks whether `R0 * 42 == 1`. If not, it terminates
execution. Otherwise, it prints the flag value.

Great, we've simplified the problem from gaining RCE to breaking the rules of math.
This should be a walk in the park!

The key here is to note _how_ the admin code checks the condition. Essentially,
the code boils down to this:

```plain
ADDI R1, ZERO, 42
MUL R2, R0, R1
SUBI R2, R2, 1
RETNZ R2
// Print flag
```

Which is equivalent to:

```plain
R1 = ZERO + 42
R2 = R0 * R1
R2 = R2 - 1
RETNZ R2
// Print flag
```

Do you see the problem here? There isn't any, right? Granted, it would've been more
efficient to replace the first two instructions with a single `MULI`, but otherwise
the code is sound, right?

Well... The code is sound only if the `ZERO` register is actually `0`. If, say,
this register were to become `-41`, and `R0` were to become `1`, then the check
would pass and we'd get the flag!

Let's see if we can't make it so that `ZERO == -41`.

## You pop what you push

We already know that direct assignments to the `ZERO` register are forbidden.
What about indirect assignments?

Remember those `PUSHCTX` and `POPCTX` instructions? They push and pop all registers
to and from the stack, respectively. But surely, you would say, `PUSHCTX` wouldn't push
the `ZERO` register, right? What's the point, since it's always `0`? And therefore,
`POPCTX` wouldn't pop it off the stack, right?

Except they do.

## How babies are made

Now it's only a matter of generating the payload, which will do the following:

1. Set `R0` to `1`.
2. Push a fake register context onto the stack, such that the `ZERO` register in the
   context is set to `-41`.
3. Pop the context off the stack.

Lucky for us, there is already a payload generator provided with the challenge.

## No payload survives contact with the target machine

We run the payload and get... garbage. Shouldn't this have worked?

![First output from running the payload](/img/baby-risc-gibberish.png)

The problem is that this RISC architecture does not have a way to load an immediate
value into a register. Instead, we have to resort to things like `ADDI R0, ZERO, 42`.
This is precisely what the admin code generator is doing - emitting a bunch of
`ADDI` instructions to load the flag into a register, 4 bytes at a time.

Under normal circumstances this would've worked fine, except we just changed the value
of `ZERO`. Fortunately, this is reversible. We just have to collect all the bytes
printed by the simulator, add `41` to each `DWORD` (since the original code
added `-41`), then stick everything back together.

`FIN`


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://archive.org/download/shabak-challenge-2021/shabak-challenge-2021.zip/
    "BabyRISC challenge files"
