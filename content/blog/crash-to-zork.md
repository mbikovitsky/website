---
title: "Crash to Zork"
date: 2020-05-02T19:36:27+03:00
---

Some years ago, when I was just getting into Windows kernel development,
I stumbled upon an unusual function: [`DbgPrompt`][DbgPrompt]. Somewhere, some
driver developer needed the ability to read input from the currently attached
kernel debugger, and so this function was added to the kernel's public API.
For me, it sparked an idea: if a driver can read text from- and write text to-, the
attached debugger, why not use it to play a little game?

Specifically, let's play Zork:
![Zork in the debugger](/zork.gif)

The idea is simple: if the system crashes (BSoDs) while the driver is loaded, and
a kernel debugger happens to be attached, then before the system reboots the driver will
ask whether the human on the other side wants to play some interactive fiction.

For the impatient, the code is available [here][source]. Below, I present some
of the challenges in implementing this kind of thing.

## A little history

For those unfamiliar, Zork is an interactive fiction game. Put simply - the game
presents a textual description of the environment, and the player types commands
such as "get lamp" or "hit troll with sword". This is a gross oversimplification
of the genre, but for our purposes it will do.

In 1980, when Zork came out, there were a lot of different
home computer systems on the market. Manually porting the game to every single
system would have taken a huge amount of time, so instead Infocom opted to develop
a virtual machine - the [Z-Machine][Z-Machine]. This way, they would only have to
implement a custom interpreter for each system, not port the whole game codebase.

Nowadays, if one want to play any of the old Infocom games (or indeed any of the
thousands of new games built upon the Z-Machine long after Infocom closed down), there
are several modern interpreters available. One of the most popular is [Frotz][Frotz].
Since it's open source, and since I did not know of any other interpreters at the time,
that's what I based my implementation on.

## Checking for bugs

So the idea is to run Zork when the system crashes, or "bug checks",
to use the technical term. The Windows kernel allows drivers to register a callback,
to be notified when a bug check occurs
([`KeRegisterBugCheckCallback`][KeRegisterBugCheckCallback]). The intended use case for
this facility is for drivers to save additional information into the crash dump,
to assist debugging. In our case, the game will be run inside the callback.

Running inside a bug check callback presents its own challenges, however. For one,
the IRQL is set to `HIGH_LEVEL`, making it impossible to use pretty much any kernel API.
More on that below.

## It is pitch black. You are likely to encounter linker errors.

Lucky for me, the Frotz codebase already contained an implementation of a "dumb"
interface - no graphics support, no sound, minimal support for terminal features
such as colors. Taking that as a starting point, I set off to porting the code
for the Windows kernel.

Frotz is already written to be portable (it even supports DOS!), so most of it
compiled without errors. The main problem was its reliance on userland APIs that
are not available in the kernel. The most troublesome: `malloc`/`free`, `fopen` et al.,
and `exit`.

How do we solve this problem? Easy - we `#define` all the troublemakers to point
to our own functions. Slight problem: although the kernel does have a memory allocator
([`ExAllocatePoolWithTag`][ExAllocatePoolWithTag]), it cannot be called at `HIGH_LEVEL`.
Same with the file handling routines.

To work around the memory allocation problem, I decided to use a third-party allocator.
Specifically, [this one][memmgr] by Eli Bendersky. It allocates memory from a static
buffer, and is simple enough to be included in kernel code.

What about file handling? Although I would've liked to present the user with a choice
of which game to load, it is just not possible to access files at `HIGH_LEVEL`. (Yes,
writing the crash dump *is* technically accessing a file, but that's a *really*
special case.) Instead, I hard-coded the game file (the Z-Machine "image") as a static
array.

Finally, `exit`. When Frotz encounters a fatal error, it calls the function `os_fatal`,
which should terminate the process. (Did I mention that all platform-specific
functionality is wrapped into `os_` functions, so all a new Frotz port has to
implement is these functions?) The Dumb implementation simply calls `exit`.
In our case, there is no process to terminate, but we still need to somehow return from
our bug check callback and let the system shut down. My solution?
`ExRaiseStatus(STATUS_UNSUCCESSFUL)`. This raises a SEH exception, which is caught
by the bug check callback, which then discards it and returns cleanly. There are
no resources to clean up, and even if there were - the system is wrecked anyway :)

## On display

Final hurdle - how to handle screen output? Although we can output strings to
the debugger, most games require somewhat fancier features, such as printing a character
at a specific point on the screen. The workaround here is to maintain an internal
screen buffer. Next question: when do we output the contents of the buffer?
Doing so every time the buffer is modified is out of the question, since we're using
a serial port for debugging, and the bitrate is not that high. Instead, we can output
the contents whenever user input is requested. Since classic IF games are very
serial in their flow (print text, ask for input, repeat), this works out nicely.

## That's it?

Pretty much. There realy isn't that much code involved in porting Frotz to the kernel
(apart from the memory allocator). True, this version won't play the fancier
Z-Machine games, but that was never the intention.

Next time (whenever that may be): I port this to the Windows 98 kernel.
Accepting bets on how many goats will be sacrificed in the process. Donations of goats
also welcome.


[DbgPrompt]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-dbgprompt
    "DbgPrompt function documentation"

[source]: https://github.com/mbikovitsky/frotz/tree/crash-to-frotz/src/crash
    "Crash to Zork source code"

[Z-Machine]: https://en.wikipedia.org/wiki/Z-machine
    "Z-Machine - Wikipedia"

[Frotz]: https://davidgriffith.gitlab.io/frotz/
    "Frotz Z-Machine interpreter"

[KeRegisterBugCheckCallback]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterbugcheckcallback
    "KeRegisterBugCheckCallback function documentation"

[ExAllocatePoolWithTag]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag
    "ExAllocatePoolWithTag function documentation"

[memmgr]: https://eli.thegreenplace.net/2008/10/17/memmgr-a-fixed-pool-memory-allocator/
    "memmgr - a fixed-pool memory allocator"
