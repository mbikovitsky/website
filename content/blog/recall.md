---
title: "Shabak Challenge 2021: Recall"
date: 2021-01-29
---

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

## Introduction

The [challenge][Challenge] description reads:

> Feel free to run your binary and use our tracer-call® services!
>
> We made sure you won't be able to read the flag anyway ;)

Well, that's not very much to go on, is it? At least we don't have a lot of code files
to look at, so that's something. It looks like we have some sort of sandbox, and
a sample executable to run inside it.

Let's start with the sandbox.

## Boxing the sand

Looking at the `main` function in `sandbox.c`, we can see that the sandbox:

1. Checks that the Linux kernel version is suitable for running the sandbox.
2. Reads an ELF from `stdin`.
3. Checks it for some stuff.
4. Initializes the protected region. _Oooh, that's interesting_.
5. Forks a child process.
6. Does different things in the parent and the child.

Now, I personally don't know much about ELFs, but a quick glance at the `elf_check`
function seems to indicate that any sections and segments within a valid ELF
(valid for the sandbox, that is) cannot reside in the protected region. So basically,
no link-time shenanigans for us.

What about this protected region? The initialization function just creates a temporary
file and returns its fd, but the really interesting stuff happens in `parent_execute`.

This function sets an execution timeout for the sandboxed process, attaches to it
via `ptrace`, then waits for the child to `execve` the actual payload executable
(remember that we `fork`-ed the child). When that's done, the parent injects
some syscalls (`inject_initial_syscalls`) into the child. Specifically:

1. `mmap` the protected region at a fixed address.
2. `mprotect` it with `PROT_NONE`, so that reads and writes are impossible.
3. Close the protected region's fd, so we can't read from it.

_Note_: it's quite easy to get lost in all the framework code in the sandbox, i.e.
all the code that moves stuff around, massages memory to inject syscalls, etc. I know
I was tempted to dive into all this while I was solving the challenge. However,
our first priority here is to get our bearings - undersrand at a high level what
the code does. We can always come back later if we think something warrants further
investigation.

Finally, the parent goes into a loop inside `handle_tracer_calls`. This loops waits
for the child to make a syscall, and if it's the special "tracer call" - handles it.
The same code also disallows further calls to `execve` (since that would be a pretty
easy sandbox escape).

Right, so that's the parent. What about the child? After the fork, the child installs
some limits on its own memory usage (`install_resource_limits`) and also on the
syscalls it can use (`install_seccomp_filter`). Finally, it `execve`-s the payload.

What syscalls can we use? Not many, really. Notably, we can't open files, so
we can't easily read the protected region from disk.

So that's the sandbox handled. Well, almost. There's still the matter of
the "tracer calls".

## Etch A Sketch

Looking at `handle_single_tracer_call`, we can see that the "tracer" exposes several
things for us:

1. NOP.
2. Clearing the protected region.
3. Writing the flag to the protected region.
4. Calculating a checksum on the memory of the tracee.
5. Getting/setting values.

It's a pretty safe bet that we're going to have to use the "tracer-call" that places
the flag in the protected region. Let's try to narrow down the list of interesting
calls further.

The NOP call, as expected, doesn't do anything. Also, from the looks of it, it doesn't
have any potential for interesting shenanigans.

The call for clearing the protected region just calls `memset` on it. Again, doesn't
look like anything interesting.

The calls for getting/setting values allow us to get/set values in 256-element
array of `uint64_t`s. The bounds checking looks solid, so there doesn't seem to be any
potential for memory corruption.

So, we're left with the checksum "tracer-call". Here's its code:

```c
// Checksum tracer-call is the following signature:
// checksum(void * address, size_t * size, uint8_t * checksum)
//  address - memory to checksum
//  size - contains size to checksum
//  checksum - 1 bytes memory that checksum will be written to
// Return 0 on success, or '-error' on error (standard errno numbers).
static int tracer_call_checksum_tracee_memory(tracer_data_t * tracer_data,
                                              uint64_t * call_result,
                                              void * tracee_memory_to_checksum,
                                              uint32_t * tracee_size_to_checksum,
                                              uint8_t * tracee_checksum_result)
{
    int ret = 0;
    uint32_t length_to_checksum = 0;
    uint8_t * memory_to_checksum = NULL;
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t res = 0;
    uint8_t checksum_result = 0;

    if (read_tracee_dword(tracer_data, tracee_size_to_checksum, &length_to_checksum) == -1)
    {
        *call_result = -EFAULT;
        goto cleanup;
    }

    // Validate we don't checksum protected region
    if (is_in_protected_region(tracee_memory_to_checksum, length_to_checksum))
    {
        *call_result = -EPERM;
        goto cleanup;
    }

    // Calculate the checksum
    memory_to_checksum = (uint8_t *)malloc(length_to_checksum);
    if (memory_to_checksum == NULL)
    {
        *call_result = -ENOMEM;
        goto cleanup;
    }

    local_iov.iov_base = memory_to_checksum;
    local_iov.iov_len = length_to_checksum;
    remote_iov.iov_base = tracee_memory_to_checksum;
    remote_iov.iov_len = length_to_checksum;
    errno = 0;
    res = process_vm_readv(tracer_data->child_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (res != length_to_checksum)
    {
        if (res != -1)
        {
            // Partial read
            *call_result = -E2BIG;
        }
        else if (errno != ESRCH)
        {
            *call_result = -errno;
        }
        else
        {
            // Fatal error
            ret = -1;
        }
        goto cleanup;
    }

    for (size_t i = 0; i < length_to_checksum; ++i)
    {
        checksum_result ^= memory_to_checksum[i];
    }

    // Return result
    if (is_in_protected_region(tracee_checksum_result, sizeof(checksum_result)))
    {
        *call_result = -EPERM;
        goto cleanup;
    }
    local_iov.iov_base = &checksum_result;
    local_iov.iov_len = sizeof(checksum_result);
    remote_iov.iov_base = tracee_checksum_result;
    remote_iov.iov_len = sizeof(checksum_result);
    errno = 0;
    res = process_vm_writev(tracer_data->child_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (res == -1)
    {
        if (errno != ESRCH)
        {
            *call_result = -errno;
        }
        else
        {
            // Fatal error
            ret = -1;
        }
        goto cleanup;
    }

    // Success
    *call_result = 0;

cleanup:
    if (memory_to_checksum != NULL)
    {
        free(memory_to_checksum);
    }
    return ret;
}
```

In essence, this "tracer-call" performs the following:

1. Checks that the memory to checksum does not overlap the protected region (otherwise,
   we could simply checksum each individial byte, and thus read the whole region).
2. Allocates enough memory to hold the memory to be check-summed.
3. Reads the memory into the newly-allocated buffer.
4. Calculates the checksum, by XOR-ing all the bytes.
5. Writes the result back, while checking that the output variable does not reside in
   the protected region.

## A glimpse of forbidden knowledge

So, what can we do with this? At first glance, this looks perfectly normal. Except,
there's something strange: the size of the memory area to checksum is given as
a pointer. And what's more, upon closer examination, the function `read_tracee_dword`
does not verify that the address it is given does not lie within the protected region.

But how is that helpful? If we pass an address within the protected region
as the size parameter, we'll just get the checksum of a region of memory with
an arbitrary size. What's more likely, however, is that the function will fail
to allocate enough memory, since a DWORD consisting of printable characters is pretty
large.

What we really want to do is get the value of the size parameter back into our process.
It is not written back directly by the tracer, so we can't get the literal number.
But, perhaps there is a way to learn something _about_ this number.
Given that we completely control the beginning of the memory range to checksum,
and given an unknown size of said range, what can we learn about the size by calling
the tracer?

We know that if the range overlaps the protected region the tracer will
fail with `EPERM`, since that's the first check it performs. If it doesn't,
then the tracer will either succeed, or fail with some other error code
(since `EPERM` is pretty unusual). We also know that the protected range starts at
$\mathtt{0x600000000000}$. Therefore, given any two addresses $S$ and $P$ within our
process, with $P < \mathtt{0x600000000000}$, we can use the tracer to tell us
whether[^1]

$$P + *S \ge \mathtt{0x600000000000}$$

In fact, since the maximum value of a DWORD is $\mathtt{0xFFFFFFFF}$,
it is sufficient for $P$ to be in the closed range

$$\[\mathtt{0x600000000000} - \mathtt{0xFFFFFFFF}, \mathtt{0x600000000000}\]$$

Finally, note that for _any_ address $S$ there exists an address $P$ within this range
such that

$$P + *S = \mathtt{0x600000000000}$$

Armed with these observations we can conclude that if we don't know the value stored at
some address $S$, we can instead find an address $P$ that satisfies the equality above,
which will tell us the value at $S$.

How do we find this $P$? The naive approach would be to scan all addresses starting
from $\mathtt{0x600000000000}$ and going downwards, and return the last address
for which the tracer _does not_ fail with `EPERM`. However, this is wildly inefficient,
since in the worst case we're going to scan $2^{32}$ addresses. A better solution
is to use binary search. Specifically, we need the [variant][Binary search] that finds
the leftmost element.

## Putting it all together

We have a procedure for leaking a single DWORD out of the protected region. To read
the complete flag we could just go over the whole page, but there's a better way:
since we know the flag is textual, we can stop our scan once we encounter a DWORD
that ends with a zero byte. To be sure that there are zero bytes after the flag
we can use the "tracer-call" that zeroes-out the protected region before loading
the flag into it.

And that's it! Side channels FTW.


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://github.com/mbikovitsky/shabak-challenge-2021/tree/main/Pwn/2%20-%20Recall
    "Recall challenge files"

[Binary search]: https://en.wikipedia.org/w/index.php?title=Binary_search_algorithm&oldid=1002025819#Procedure_for_finding_the_leftmost_element
    "Binary search algorithm that finds the leftmost element"

[^1]: Yes, that's the correct inequality. The `is_in_protected_region` function
      returns `true` if the end of a memory region falls exactly on the start
      of the protected region. Technically, this is an off-by-one error :)
