---
title: "Shabak Challenge 2021: Paging"
date: 2021-02-02
summary: Sometimes one bit is enough
---

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

- [Introduction](#introduction)
- [A high-level overview](#a-high-level-overview)
  - [Paging](#paging)
  - [Hypercalls](#hypercalls)
- [Yes, and...](#yes-and)
- [A bit too far](#a-bit-too-far)
- [Assemble it yourself](#assemble-it-yourself)
- [Some more "features"](#some-more-features)

# Introduction

The [challenge][Challenge] description reads:

> After going through the xv6 Memory Management chapter, I decided to challenge myself
> and implement my own paging mechanism! (In ARM, of course!).
>
> No chance for bugs here, right?

Right, so we're going to be dealing with page tables and ARM code. The referenced xv6
book can be found [here][xv6-rev11][^1], and should provide the necessary background
on paging (I haven't read it, personally 😎). As for the ARM part, I highly recommend
the introduction over at [Azeria Labs][ARM-intro].

With the introductions done, let's get going.

# A high-level overview

Looking at the supplied code, there are a lot of moving parts.
Before we can get the flag, we'll have to understand how the system works.

The system is an ARMv7-A emulator (as evidenced by the message printed on startup),
based on [Unicorn][Unicorn]. On startup, it reads at most 2048 lines of ARM assembly
code, assembles it using [Keystone][Keystone], places it at address `0x4000`,
then proceeds to execute it.
Note that ARMv7-A is a 32-bit system, i.e. pointers are 32-bit in size.

The emulator also provides special services to the emulated code, via the ARM `SVC`
instruction:

1. Enabling and disabling paging.
2. Setting the `TTBR0` register.
3. Invoking a "hypercall".
4. Authentication.
5. Terminating the emulator.

## Paging

Looking inside `paging.py`, we can see that we have a two-level paging structure.
The physical address of the Page Directory is stored in `TTBR0`, the PD contains
the physical addresses of Page Tables, which in turn point to actual pages with data.
Pages are 4kB in size.

Looking at the `v_to_p` function, and the functions it calls, we can construct a picture
of how a virtual address is broken down[^4]:

```plain{linenos=false}
+----------+----------+------------+
|          |          |            |
|   PDE    |   PTE    |   Offset   |
|          |          |            |
+----------+----------+------------+
    10b        10b         12b
```

That is, the 10 topmost bits are an index into the Page Directory, the next 10 bits
are an index into the Page Table, and the final 12 bits are an offset into the page.

What do the entries in a Page Directory/Table look like? The structure is defined
in `entry.py`[^2]:

```plain{linenos=false}
+---------------------+--------+--+-----+--------+-----+-------+
|                     |        |  |     |        |     |       |
|         PFN         |Reserved|NX|Dirty|Accessed|Write|Present|
|                     |        |  |     |        |     |       |
+---------------------+--------+--+-----+--------+-----+-------+
          20b             7b    1b   1b     1b      1b     1b
```

The `Present` bit indicates whether this entry points to a valid table or page.
If at any point in the virtual address translation process the emulator encounters
an entry with `Present == 0`, a page fault is generated.

The `Write` bit indicates whether the target page is writeable. For a page
to be writable, all the entries leading up to it must have the `Write` bit set.

The `Accessed` bit is set to `1` whenever an entry is accessed during translation.

The `Dirty` bit is set whenever an entry is accessed during translation,
*and* the target page is being accessed for a write operation.

The `NX` bit indicates whether the target page is Not eXecutable. For a page
to be executable, all the entries leading up to it must have the `NX` bit set to `0`.

## Hypercalls

The hypercall mechanism provides a lot of functionality, and we'll get back to that
later on. For now, we can note the following:

1. To invoke a hypercall, the code should place the hypercall number in `R0`,
   and up to two arguments in `R1` and `R2` (see `hook_intr` in `main.py`).
2. Hypercalls can only be called when paging is enabled (see `run_hypercall` in
   `paging.py`).
3. Hypercalls require authentication (see `run` in `hypercall.py`),
   but the authentication service is not implemented (see `authenticate` in
   `hypercall.py`).
4. The hypercall mechanism stores some configuration in the first page of physical
   memory (see `run_hypercall` in `paging.py`).
   - This configuration is saved to disk when the hypercall mechanism is deactivated.
   - The configuration does not appear to be *read* from disk on activation, however.

Regarding the hypercall configuration, it has the following format
(see `_settings_fmt` in the `Hypercall` class in `hypercall.py`):

<a name="hypercall-config"></a>

```c++
struct hypercall_config
{
    uint8_t     groups;
    char        time_activated[19];

    struct
    {
        uint8_t group_perm;
    } group_profiles[groups];
};
```

# Yes, and...

We now understand, in broad strokes, how the system works. However, we are no closer
to understanding how we should go about retrieving the flag. The emulator does
not read the flag by itself, and it does not expose any functionality
for reading files or executing arbitrary commands.

Or does it?

A closer inspection of `Hypercall.save_state`, the function that saves the hypercall
configuration to disk, reveals that it does so in a very peculiar way:

```py3
# consts.py
ECHO = 'echo'
INTO_FILE = '>'
STATES_FOLDER = "user_states"

# hypercall.py
class Hypercall:
    def __init__(self):
        # ...
        self._open_process = os.system
        # ...

    def save_state(self, hypercall_settings, file_name):
        assert ".." not in file_name and "/" not in file_name and "\\" not in file_name
        self._open_process(
            ECHO +
            f' "{hypercall_settings}"' +
            INTO_FILE +
            ' ' +
            STATES_FOLDER +
            os.path.sep +
            f'{file_name}')
```

In essence, this function invokes:

```bash
echo "<hypercall_settings>" > user_states/<file_name>
```

Can we use this to our advantage? Well, if we could control the filename we could set
it to, for instance `a;cat flag`, which would result in the following command:

```bash
echo "<hypercall_settings>" > user_states/a;cat flag
```

This will save the configuration to a file called `user_states/a`, and then run
`cat flag`[^3].

Lucky for us, we *can* set the filename! In theory. The filename used is the
`time_activated` field in the hypercall configuration, and hypercall no. 14 can be
used to set this field to an arbitrary value.

And so we have our plan:

1. Set up paging.
2. Enable paging.
3. Authenticate.
4. Use hypercall 14 to set the timestamp to `a;cat flag`.
5. Deactivate paging to execute the command.

Except... authentication doesn't work.

# A bit too far

The way authentication is *meant* to work (according to the code comments), is by
setting `self._curr_perm` to `Hypercall.GROUP_PERM_SUPER` (by default the value is
`Hypercall.GROUP_PERM_USER`). When a hypercall is invoked, the implementation goes
over all [group profiles](#hypercall-config) and if any group has a `group_perm`
field equal to `self._curr_perm`, then access is granted.

There is no code in the emulator that manipulates `self._curr_perm`, so we can't
go that way. But perhaps we can manipulate the hypercall settings to grant access
to `Hypercall.GROUP_PERM_USER`.

Since the settings are stored in the first physical page, can we just write there?
We can write to that page while paging is disabled, however as soon as we enable it
that page gets replaced with the default hypercall configuration (see `activate`
in `paging.py`). When paging is enabled, writes to the first page raise a page fault
(see `v_to_p` in `paging.py`).

Okay, so we'll have to write to the first physical page when paging is enabled, but
we can't do it directly. What other flows in the emulator result in writes to physical
memory? Perhaps we can abuse some of them.

The only writes to physical memory inside `paging.py` occur in `_set_physical_mem`
and in `_write_memory`. The first function is called only on the activation of paging,
and doesn't look very interesting. The second function, however, gets called from
several places:

1. From `set_p_value`, which is called when a write operation occurs in the emulated
   code.
2. From `run_hypercall`, to store the updated hypercall settings page.
3. From `_validate_entry`, to set the `Accessed` and `Dirty` bits in a table entry.

The first case is not interesting, since `set_p_value` is called only after
`v_to_p` translates a virtual address to a physical one, and this will fail if we
reference the first physical page.

The second case is not interesting because `Hypercall.run` throws an exception
if a hypercall is invoked without prior authentication, and so `Paging.run_hypercall`
exits without storing anything to the first page.

What about the third case? This results in a write of one or two bits to a table entry.
Specifically, bit 2 is always set to 1, and bit 3 is set to 1 if we're accessing
a page for writing. And note: there is no check here that we aren't writing
to the first physical page! Is this useful?

But wait, what do we actually want to achieve here? We want to allow hypercall access
for `Hypercall.GROUP_PERM_USER`. There are two ways to do this:

1. Set the `group_perm` field of the default (and only) group to
   `Hypercall.GROUP_PERM_USER == 0`.
2. Add a new group with a `group_perm` of `0`. This requires increasing
   the `groups` field and setting the `group_perm` of the new group to `0`.

The first option is immediately out, since we can only write 1 bits. The second option,
however... Since the hypercall page is initially zeroed-out (see `pack_default_settings`
in `hypercall.py`), "simply" increasing `groups` will give us a new group
with `Hypercall.GROUP_PERM_USER`!

Conveniently for us, the paging structures are little-endian. If we treat
the first physical page as a page table, then the first entry in it will look like
this:

```plain{linenos=false}
+---------------------+----------------------------------------+
|                     |                                        |
|time_activated[0...2]|                groups                  |
|                     |                                        |
+---------------------+----------------------------------------+

+---------------------+--------+--+-----+--------+-----+-------+
|                     |        |  |     |        |     |       |
| Rest of table entry |Reserved|NX|Dirty|Accessed|Write|Present|
|                     |        |  |     |        |     |       |
+---------------------+--------+--+-----+--------+-----+-------+
          24b             3b    1b   1b     1b      1b     1b
```

This means that merely reading from a page that goes through this "table entry"
will change `groups` from `0b1 == 1` to `0b101 == 5`, effectively authenticating us!

Note that the page we're accessing need not actually exist in physical memory.
In this case, the paging mechanism will throw an exception, which will be suppressed
inside `hook_read` in `main.py`.

# Assemble it yourself

Our plan now looks like this:

1. Set up paging:
   1. Create a Page Directory somewhere in physical memory.
   2. Map physical address 0x4000 to virtual address 0x4000, so that our code
      will continue executing after paging is enabled.
   3. Make one of the PDEs in the Page Directory point to the first physical page.
   4. Set `TTBR0` to the physical address of the Page Directory.
2. Enable paging.
3. Authenticate by reading from the magic page.
4. Use hypercall 14 to set the timestamp to `a;cat flag`.
5. Deactivate paging to execute the command.

Note that the emulator disallows the use of `.` directives in the assembly code,
so we can't use `.ascii` to bring the command with us. Handling this is left
as an exercise for the reader 😎.

# Some more "features"

While looking into the paging implementation, I noticed it is possible to extend
the amount of physical memory by 4 bytes at a time. In fact, one of my early solution
attempts made use of this. See if you can find this "feature" 👾.

`FIN`


[^1]: This appears to be the last edition of the book that targets the x86 architecture.
      Beginning with the [class of 2019][xv6-port], xv6 was ported to RISC-V.

[^2]: PFN is short for Page Frame Number, i.e. the number of the physical page
      this entry points to. Conveniently, zeroing out all the bits except the PFN
      yields the physical address of the page.

[^3]: For more such fun shenanigans, see [here][shell-injection].

[^4]: All the ASCII diagrams in this post were made using
      [ASCIIFlow Infinity][asciiflow].


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://archive.org/download/shabak-challenge-2021/shabak-challenge-2021.zip/
    "Paging challenge files"

[xv6-rev11]: https://pdos.csail.mit.edu/6.828/2018/xv6/book-rev11.pdf
    "xv6 - a simple, Unix-like teaching operating system"

[xv6-port]: https://pdos.csail.mit.edu/6.828/2019/xv6.html
    "6.S081: Operating System Engineering, 2019"

[ARM-intro]: https://azeria-labs.com/writing-arm-assembly-part-1/
    "ARM Assembly Basics"

[Unicorn]: https://www.unicorn-engine.org/
    "Unicorn - The Ultimate CPU emulator"

[Keystone]: https://www.keystone-engine.org/
    "Keystone - The Ultimate Assembler"

[shell-injection]: https://en.wikipedia.org/w/index.php?title=Code_injection&oldid=1003675714#Shell_injection
    "Shell injection - Wikipedia"

[asciiflow]: http://asciiflow.com/
    "ASCIIFlow Infinity"
