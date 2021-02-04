---
title: "Shabak Challenge 2021: shabaKernel"
date: 2021-02-04
summary: 0x70C 0xB4C 0xB4C 0x5B4 0x1E8 0x830 0xA24 0x208 0x028 0x140 0x5EC
---

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

- [Introduction](#introduction)
- [Part I: A kernel of truth](#part-i-a-kernel-of-truth)
  - [Get a load of this](#get-a-load-of-this)
  - [Master builder](#master-builder)
  - [This just in](#this-just-in)
  - [Cherry-pick](#cherry-pick)
- [Part II: The Valley of Fear](#part-ii-the-valley-of-fear)
  - [Where we're going we don't need `libc`](#where-were-going-we-dont-need-libc)
  - [A skip and a hop](#a-skip-and-a-hop)

## Introduction

The [challenge][Challenge] description reads:

> This binary is not an elf. So what is it?
>
> Load the .ko file and find out...
>
> Use the image:
>
> [http://uec-images.ubuntu.com/releases/focal/release-20201210/][image]
>
> Good luck!

Unlike Windows, the Linux kernel API --- the API inside the kernel,
not the syscall API --- can, and does, change between releases. So if we're going to be
reversing kernel modules, we best have the correct kernel sources close to hand.

The supplied image is of Ubuntu 20.04, which according to [this][release-notes] has
kernel version 5.4. Instead of downloading the complete source tree, I found
[this][source-browser] nice website that can search through the kernel sources.

So, let's get started.

## Part I: A kernel of truth

We take `loader.ko`, throw it into our [favorite decompiler][Ghidra], and see what's
what:

![shabaKernel exported symbols](/img/shabakernel-exported-symbols.png)

The `stateless_rc4` function hints that perhaps the other binary is encrypted with
[RC4][RC4], and the `build_key` function probably constructs the decryption key.
There's also `load_magen_binary` that looks like the "main" function here.

However, it accepts some unknown parameter which likely describes the binary being
loaded. So let's table it for now, and instead take a look at `init_module`.
This function does only one thing: calls `__register_binfmt` with the address
of the global variable `magen_fmt`.

This rings a bell: [binfmt_misc][binfmt] is the Linux kernel feature that allows
us to define custom file formats as executable. Looks like in this case we're dealing
with the lower-level variant of the same feature. A quick search yields
the [structure][linux_binfmt] being passed at registration:

```c++
/*
 * This structure defines the functions that are used to load the binary formats that
 * linux accepts.
 */
struct linux_binfmt {
    struct list_head lh;
    struct module *module;
    int (*load_binary)(struct linux_binprm *);
    int (*load_shlib)(struct file *);
    int (*core_dump)(struct coredump_params *cprm);
    unsigned long min_coredump; /* minimal dump size */
} __randomize_layout;
```

And, sure enough, the `load_binary` field points to our old friend `load_magen_binary`.
We also learn that the function accepts a pointer to [`linux_binprm`][linux_binprm]
as its only parameter. This structure is rather large, but it's worth our time to get it
into Ghidra, since we don't know yet what fields `load_magen_binary` uses.

### Get a load of this

We can't put this off any longer. Time to see how the binary is loaded.

The `load_magen_binary` function begins with what looks like parameter validation.
The interesting bit is here:

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
{{< highlight "c++" "lineanchors=load-binary-raw,anchorlinenos=true" >}}
lVar6 = __kmalloc(*(undefined4 *)(binprm->buf + 5), 0xcc0);
if (lVar6 != 0) {
  lVar7 = kmem_cache_alloc_trace(_DAT_001010d0, 0xcc0, 0x12);
  if (lVar7 != 0) {
    iVar4 = build_key(binprm->buf + 9,
                      lVar7,
                      *(int *)(binprm->buf + 5) - 9,
                      &local_44);
    if (iVar4 != -1) {
      local_40 = (ulong)local_44 + 9;
      uVar10 = *(int *)(binprm->buf + 5) - 9 - local_44;
      uVar5 = kernel_read(binprm->file,
                          lVar6,
                          uVar10,
                          &local_40);
      if (uVar10 == uVar5) {
        stateless_rc4(lVar7, 0x12, lVar6, uVar10);
{{< /highlight >}}
<!-- markdownlint-restore -->

This is the output from Ghidra, I just cleaned it up a little. So, what's going on here?

In [line 1](#load-binary-raw-1), the code reads a DWORD at offset 5 in the `buf` field
of the `linux_binprm` structure, and allocates a buffer with this size.
It's a fair guess that this field contains part of the binary file being loaded.
Indeed, let's take a look at our binary:

```hexdump
0000h: 4D 41 47 45 4E 19 06 00 00 52 2F 62 69 6E 2F 62  MAGEN....R/bin/b
0010h: 61 73 68 52 2F 62 69 6E 2F 70 69 6E 67 52 2F 62  ashR/bin/pingR/b
0020h: 69 6E 2F 67 72 65 70 52 2F 75 73 72 2F 62 69 6E  in/grepR/usr/bin
0030h: 2F 74 65 6C 6E 65 74 52 2F 73 62 69 6E 2F 69 6E  /telnetR/sbin/in
0040h: 69 74 52 2F 73 62 69 6E 2F 69 6E 73 6D 6F 64 52  itR/sbin/insmodR
0050h: 5A                                               Z
```

The first 5 bytes are the magic string `MAGEN`[^1], and so at offset 5 we have the
DWORD `0x00000619 == 1561`. In fact, this is the exact size of the binary! Great, we're
making progress.

In [line 3](#load-binary-raw-3) the code allocates a buffer of size `0x12 == 18`.

Then, in [lines 5-8](#load-binary-raw-5), there is a call to build the decryption key
(presumably). What's being passed here?

1. The first argument is a pointer to the input buffer, at offset 9. Looking at the file,
   we can see that this is the beginning of a section with a bunch of strings.
2. The second argument is the 18-byte buffer we just allocated, so presumably
   this will receive the decryption key.
3. The third argument is the size of the file minus 9, so really it's just the size
   without the magic and size fields.
4. The fourth argument points to some local variable, `local_44`.

Can we deduce what that last local variable is? Later on, it's used in some calculations
in [lines 10-11](#load-binary-raw-10), and then the results are passed as arguments
to `kernel_read`. Here's `kernel_read`'s [signature][kernel_read]:

```c++
ssize_t kernel_read(struct file *file,
                    void *buf,
                    size_t count,
                    loff_t *pos);
```

The fourth parameter is the offset within the file to read from, and we're passing it:

```c++
(ulong)local_44 + 9
```

So `local_44` is an offset within the remainder of the file, the remainder being
what comes after the magic and size fields.

The third parameter is the number of bytes to read from the file, and we're passing it:

```c++
*(int *)(binprm->buf + 5) - 9 - local_44
```

Which is the size of the block of bytes starting from `local_44 + 9` until the end of
the file.

Later on, in [line 17](#load-binary-raw-17), the data read from the file is passed
to the decryption function, so presumably `local_44 + 9` is the offset of the code
to be executed within the file.

Armed with these observations, we can now clean up the decompiled code:

```c++
pvCode = __kmalloc(*(uint *)(binprm->buf + 5), 0xcc0);
if (pvCode != NULL) {
  pcRc4Key = (byte *)kmem_cache_alloc_trace(_DAT_001010d0, 0xcc0, 18);
  if (pcRc4Key != NULL) {
    nResult = build_key((byte *)(binprm->buf + 9),
                        pcRc4Key,
                        *(int *)(binprm->buf + 5) - 9,
                        &cbCodeOffset);
    if (nResult != -1) {
      cbCodeFileOffset = (ulong)cbCodeOffset + 9;
      cbCode = *(int *)(binprm->buf + 5) - 9 - cbCodeOffset;
      uVar3 = kernel_read(binprm->file,
                          pvCode,
                          cbCode,
                          &cbCodeFileOffset);
      if (cbCode == uVar3) {
        stateless_rc4(pcRc4Key, 18, pvCode, cbCode);
```

### Master builder

Time to see how the decryption key is constructed.

Ghidra does a fairly decent job of decompiling the `build_key` function,
so understanding what it does is mostly a matter of following the code.
And since the only other internal function it calls is `update_path`, there is almost no
guessing about the meaning of parameters. There are, however, several gotchas:

- At the very beginning of the function there is a call to `__fentry__`.
  AFAICT this is part of some [kernel tracing mechanism][ftrace], and usually this call
  doesn't do anything. Ghidra, however, trips up on it because it thinks
  it spoils some registers. The workaround I used is to `NOP`-out the call instruction
  in Ghidra: right-click on the instruction in the disassembler and choose "Patch
  Instruction".
- The big chunk of code in the middle of the function ([lines 45-48](#build-key-45))
  is an optimized and/or obfuscated `memcpy`, so don't get stuck reversing it 😐.

Here is the cleaned-up version of the code:

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
{{< highlight "c++" "hl_lines=29 45-48 60,lineanchors=build-key,anchorlinenos=true" >}}
int build_key(byte *pcData,
              byte *pcRc4Key,
              uint cbData,
              uint *pcbCodeOffset)
{
  int eUpdatePathResult;
  char *pszFilename;
  size_t cbFilename;
  size_t cbFilenameEndOffset;
  uint cbFilenameOffset;
  char *pcFilename;
  uint cbActualDataSize;
  uint cbFileOffset;

  *pcbCodeOffset = -1;
  memset(pcRc4Key, 0, 18);

  if ((pcData != NULL)
      && (pcRc4Key != NULL)
      && (*pcData == 'R')
      && (pszFilename = (char *)__kmalloc(cbData + 1, 0xcc0),
          pszFilename != NULL)) {
    cbFilenameEndOffset = 1;
    cbActualDataSize = 0x100;
    if (cbData < 0x101) {
      cbActualDataSize = cbData;
    }

    cbFileOffset = 0x5117;
    cbFilenameOffset = 1;
    if (1 < cbData) {
      do {
        while (true) {
          if (pcData[cbFilenameEndOffset] == 'Z') {
            kfree(pszFilename);
            *pcbCodeOffset = cbFilenameEndOffset + 1;
            return 0;
          }
          if (pcData[cbFilenameEndOffset] != 'R') {
              break;
          }
          cbFilename = cbFilenameEndOffset - cbFilenameOffset;
          pcFilename = (char *)(pcData + cbFilenameOffset);

          // ...
          // Copy filename from binfmt buffer into pszFilename
          // and add a null-terminator
          // ...

          eUpdatePathResult = update_path(pcRc4Key,
                                          pszFilename,
                                          cbFileOffset);
          if (eUpdatePathResult == -1) {
            return -1;
          }

          cbFilenameEndOffset += 1;
          cbFilenameOffset = cbFilenameEndOffset;

          cbFileOffset += 0x11;

          if (cbActualDataSize <= cbFilenameEndOffset) {
            goto LAB_00100358;
          }
        }
        cbFilenameEndOffset += 1;
      } while (cbFilenameEndOffset < cbActualDataSize);
    }
LAB_00100358:
    kfree(pszFilename);
  }

  return -1;
}
{{< /highlight >}}
<!-- markdownlint-restore -->

Recall that the "magen" binary contains a fairly long string of filenames, where
each filename begins with an `R`, and the whole list is terminated with a `Z`:

```plain
R/bin/bashR/bin/pingR/bin/grepR/usr/bin/telnetR/sbin/initR/sbin/insmodRZ
```

What `build_key` does is pass each filename to the `update_path` function
along with a file offset (but technically we don't know it's a file offset yet 😉).
For the first file, the offset is `0x5117` (see [line 29](#build-key-29)), and it is
incremented by `0x11` for each subsequent file ([line 60](#build-key-60)).

Cool, so what does `update_path` do?

### This just in

After changing the function signature in Ghidra according to what we learned from
`build_key`, we get a pretty coherent output. Here it is, after some cleanup[^2]:

```c++
int update_path(byte *pcRc4Key, char *pszFilename, uint cbOffset)
{
  void *file;
  byte *buf;
  ssize_t cbReadBytes;
  size_t nIndex;
  int eResult;
  loff_t cbOffset_;

  cbOffset_ = cbOffset;
  file = filp_open(pszFilename, 0, 0);
  if (file < (void *)0xfffffffffffff001) {
    buf = (byte *)kmem_cache_alloc_trace(_DAT_001010d0, 0xcc0, 18);
    if (buf == NULL) {
      eResult = -1;
    }
    else {
      cbReadBytes = kernel_read(file, buf, 18, &cbOffset_);
      eResult = -1;
      if (cbReadBytes == 18) {
        nIndex = 0;
        do {
          pcRc4Key[nIndex] = pcRc4Key[nIndex] ^ buf[nIndex];
          nIndex = nIndex + 1;
        } while (nIndex != 18);
        eResult = 0;
      }
      kfree(buf);
    }
    filp_close(file, NULL);
  }
  else {
    eResult = -1;
  }
  return eResult;
}
```

So we're reading 18 bytes (which is precisely the key size) from the file and XORing
the existing key with these bytes. Cool.

### Cherry-pick

We now know all we need in order to decrypt the binary. Here's how we do it:

1. Get all the files needed to construct the key from the [image][image].
2. Extract 18 bytes from each file. Start from offset `0x5117` in the first file, and
   increment the offset by `0x11` for each subsequent file.
3. XOR all these arrays to produce an 18-byte key.
4. Decrypt the remainder of the binary with this key, and the RC4 algorithm[^3].

After decryption we get a binary with some strings in it, such as
`"Good work my friend, go submit the flag"`, so it looks like we got it right 🥳.

## Part II: The Valley of Fear

We take our decrypted binary, throw it into Ghidra, and set the language to
`x86:LE:64:default:gcc`. Initially, it's a whole lot of nothing:

![Decrypted binary - first open](/img/shabakernel-shellcode.png)

Assuming that execution begins at the start of the shellcode, we hit the `D` key
and lo and behold: it's a jump deeper down. Here's what we get:

```c++
void start(void)
{
  int iVar1;
  long lVar2;
  long lVar3;

  lVar2 = FUN_0000015f(0,0,0,0);
  if (lVar2 == -1) {
    FUN_0000003c(1,0x397,4);
  }
  else {
    lVar2 = FUN_000000d8(0,0x18,3,0x22,0xffffffff,0);
    if (lVar2 == -1) {
      FUN_0000003c(1,0x39c,5);
    }
    else {
      lVar3 = FUN_000000d8(0,0xf0,3,0x22,0xffffffff,0);
      if (lVar3 == -1) {
        FUN_0000003c(1,0x39c,5);
      }
      else {
        iVar1 = FUN_00000285(lVar2);
        if (iVar1 != -1) {
          iVar1 = FUN_00000010(0,lVar3,0xf0);
          if (iVar1 == 0x19) {
            iVar1 = FUN_00000200(lVar3,lVar2,0x18,lVar2);
            if (iVar1 == 0) {
              FUN_0000003c(1,0x3d0,0x28);
            }
            else {
              FUN_0000003c(1,0x3a8,0x22);
            }
          }
          else {
            FUN_0000003c(1,0x3a8,0x22);
          }
        }
        FUN_00000121(lVar3,0xf0);
      }
      FUN_00000121(lVar2,0x18);
    }
  }
  FUN_00000145(0);
  return;
}
```

Not *too* bad, all things considered. No complicated control flow here, just plain old
"call API, exit if it fails". Let's see where this leads us.

### Where we're going we don't need `libc`

Looking at the first function, it's a wrapper around syscall number `0x65`:

![Syscall 0x65 wrapper assembly](/img/shabakernel-syscall-65.png)

Now, I have no idea what syscall `0x65` is, but [this][syscalls] page does. Apparently,
this is `ptrace`. Combined with the appropriate `man` page we can set the correct
signature for this wrapper function. In fact, most of the functions here are syscall
wrappers, and we can make quick work of them.

Here's what the code looks like now[^4]:

```c++
void start(void)
{
  int iVar1;
  long lVar2;
  void *addr;
  void *buf;
  ssize_t sVar3;

  lVar2 = ptrace(PTRACE_TRACEME,0,NULL,NULL);
  if (lVar2 == -1) {
    write(1,"Bye\n",4);
  }
  else {
    addr = mmap(NULL,0x18,3,0x22,-1,0);
    if (addr == (void *)0xffffffffffffffff) {
      write(1,"mmap\n",5);
    }
    else {
      buf = mmap(NULL,0xf0,3,0x22,-1,0);
      if (buf == (void *)0xffffffffffffffff) {
        write(1,"mmap\n",5);
      }
      else {
        iVar1 = FUN_00000285(addr);
        if (iVar1 != -1) {
          sVar3 = read(0,buf,0xf0);
          if ((int)sVar3 == 0x19) {
            iVar1 = FUN_00000200(buf,addr,0x18,addr);
            if (iVar1 == 0) {
              write(1,"Good work my friend, go submit the flag\n",0x28);
            }
            else {
              write(1,"This is not the right flag, Buddy\n",0x22);
            }
          }
          else {
            write(1,"This is not the right flag, Buddy\n",0x22);
          }
        }
        munmap(buf,0xf0);
      }
      munmap(addr,0x18);
    }
  }
  _exit(0);
  return;
}
```

The `ptrace` call is there to prevent attaching to the process with a debugger.

Then, the code allocates two buffers, `addr` and `buf`. `buf` is later used to store
user input (recall that fd 0 is `stdin`), and it appears that its contents are compared
to those of `addr`, inside `FUN_00000200`. A quick look at this function confirms
that it performs string comparison.

Onwards, to find the flag!

### A skip and a hop

So, what's inside `FUN_00000285`? Let's take a look:

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
{{< highlight "c++" "hl_lines=18,lineanchors=read-flag,anchorlinenos=true" >}}
int read_flag(char *flag)
{
  int fd;
  off_t oVar1;
  ssize_t sVar2;
  int local_8;
  int local_4;

  local_4 = 0;
  fd = open("/lib/x86_64-linux-gnu/libc.so.6",0,0);
  if (fd == -1) {
    write(1,"open\n",5);
    local_4 = -1;
  }
  else {
    local_8 = 0;
    while (local_8 < 0x18) {
      oVar1 = lseek(fd,(ulong)*(uint *)((long)local_8 * 4 + 0x1a0),0);
      if ((int)oVar1 == -1) {
        write(1,"lseek\n",5);
        local_4 = -1;
        break;
      }
      sVar2 = read(fd,flag + local_8,1);
      if ((int)sVar2 == -1) {
        local_4 = -1;
        break;
      }
      local_8 = local_8 + 1;
    }
    close(fd);
  }
  return local_4;
}
{{< /highlight >}}
<!-- markdownlint-restore -->

The function opens `/lib/x86_64-linux-gnu/libc.so.6` and reads `0x18` bytes from it,
all from different locations. The offsets are calculated on [line 18](#read-flag-18),
but what's going on there?

The strange `0x1a0` address is actually within the binary, Ghidra just failed to
recognize it as such. In fact, the assembly uses `RIP`-relative addressing,
so there's no explicit reference to `0x1a0` anywhere, it's just a by-product
of us loading the binary at address 0 in Ghidra.

So, the offsets to read from are stored in an array:

![Offsets array](/img/shabakernel-offsets-array.png)

All we have to do now is get `/lib/x86_64-linux-gnu/libc.so.6` from the [image][image]
and read the bytes at the specified offsets.

`FIN`


[^1]: Fun fact: AFAICT, this magic is not validated anywhere in `loader.ko`.

[^2]: I removed a call to `__fentry__` and some stack cookie checks.

[^3]: If, like me, you're using Python, the PyCryptodome library implements RC4
      as [ARC4][ARC4-implementation].

[^4]: The only difference between this and the Ghidra output is the inlining
      of string references. Originally, they all appear as `s_mmap_0000039c`
      and the like, or as raw integers when Ghidra fails to recognize them as
      addresses in the binary.


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://archive.org/download/shabak-challenge-2021/shabak-challenge-2021.zip/
    "shabaKernel challenge files"

[image]: http://uec-images.ubuntu.com/releases/focal/release-20201210/
    "Ubuntu 20.04 LTS (Focal Fossa) [20201210]"

[release-notes]: https://ubuntu.com/blog/ubuntu-kernel-5-4-whats-new-with-ubuntu-20-04-lts
    "Ubuntu kernel 5.4: What's new with Ubuntu 20.04 LTS"

[source-browser]: https://elixir.bootlin.com/linux/v5.4.93/source
    "Linux source code (v5.4.93) - Bootlin"

[Ghidra]: https://ghidra-sre.org/
    "Ghidra"

[RC4]: https://en.wikipedia.org/wiki/RC4
    "RC4 - Wikipedia"

[binfmt]: https://en.wikipedia.org/wiki/Binfmt_misc
    "binfmt_misc - Wikipedia"

[linux_binfmt]: https://elixir.bootlin.com/linux/v5.4.93/source/include/linux/binfmts.h#L102
    "binfmts.h - include/linux/binfmts.h - Linux source code (v5.4.93) - Bootlin"

[linux_binprm]: https://elixir.bootlin.com/linux/v5.4.93/source/include/linux/binfmts.h#L17
    "binfmts.h - include/linux/binfmts.h - Linux source code (v5.4.93) - Bootlin"

[kernel_read]: https://elixir.bootlin.com/linux/v5.4.93/source/fs/read_write.c#L432
    "read_write.c - fs/read_write.c - Linux source code (v5.4.93) - Bootlin"

[ftrace]: https://en.wikipedia.org/wiki/Ftrace
    "ftrace - Wikipedia"

[ARC4-implementation]: https://www.pycryptodome.org/en/latest/src/cipher/arc4.html
    "ARC4 - PyCryptodome 3.9.9 documentation"

[syscalls]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md
    "Chromium OS Docs - Linux System Call Table"
