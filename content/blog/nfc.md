---
title: "Shabak Challenge 2021: NFC"
date: 2021-01-27
summary: RTFM
---

**Update 2021-01-31**: Archive moved to the [Internet Archive][Challenge].

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

## Introduction

The [challenge][Challenge] description reads:

> Our target adopted a new way to keep sensitive information! They use secure NFC tags
> to keep secure and confidential information inside them.
>
> We managed to place a strong NFC reader near our target's secret NFC tag.
> Now we want to communicate with the that tag and extract the secret information from
> it.
>
> In order to connect to our reader and send commands to the tag, you just need to
> open a TCP socket to:
>
> `nfc.shieldchallenges.com 80`
>
> Each message you send on this socket will be transferred to the NFC tag,
> and the response from the tag will be sent back to you on that same socket.
>
> In addition, our sources equipped us with some information that may help you to
> communicate with the tag and extract the secret information from it:
>
> 1. A secret document from our target (attached).
> 2. An authentic message sent to the NFC tag. Due to a low signal, we managed to
>    extract only 5 bytes from the message. The message is presented below
>    (`X` stands for an unknown nibble).
>
>    `1BXXXXBEAF4930`
>
> 3. The secret information you need to extract is located somewhere in the memory
>    space of the tag, and its size is 16 characters.
>
> Good luck! We trust you!

Right off the bat, we can see that this is an unusual reversing challenge - there is
no binary to reverse! Instead, we are going to be reversing the NFC protocol.

## First impressions

We are provided with a document that describes various changes performed
to a [NTAG213][NTAG213] chip. Here's the gist:

1. Some commands have been stripped, and a special NAK code (`6h`) has been added
   to signal when an unsuppored command is issued.
2. A new command, `GET_CFG`, has been added:
   ![GET_CFG command chart](/img/nfc_get_cfg.png)

   With the various fields defined as follows:
   | Name | Code         | Description             | Length  |
   |------|--------------|-------------------------|---------|
   | Cmd  | `66h`        | Get configuration bytes | 1 byte  |
   | CRC  |              | CRC according to Ref. 1 | 2 bytes |
   | CFG0 |              | Value of CFG 0          | 4 bytes |
   | CFG1 |              | Value of CFG 1          | 4 bytes |
   | NAK  | See Table 23 | See Section 9.3         | 4-bit   |
3. The CRC algorithm is "clarified" (we'll get back to that).

We'll obviously have to dive into the full datasheet to understand all the details
of the protocol, but we can already get an idea of how it works:
1. The host sends a command to the device, with a CRC at the end.
2. The device replies either with a NAK, or with some data and a CRC.

So, what's this about a CRC?

## Bicycle, bicycle...

Ref. 1 in the datasheet refers to the ISO/IEC 14443 standard. According to the document
we received with the challenge, the standard describes two slightly different CRC
variants: CRC_A and CRC_B. So, we're going to need an implementation of the CRC
algorithm. More importantly, we need to know _which_ CRC variant to use.

_Note_: it appears that the CRC paragraph in the document is taken from
https://hub.zhovner.com/tools/nfc/ :)

For the first problem, some Googling leads to the [following][StackOverflow]
helpful Stack Overflow answer, which points to an implementation of the two CRC
variants inside [libnfc][libnfc].

As for the second problem, we _could_ go the easy way and just test both variants
and see what works against the remote machine. However, мы не ищем лёгких путей[^1],
so we're going to try and figure out what the spec. says.

Some [Googling][standard-search] for ISO/IEC 14443 reveals that
the standard actually consists of 4 parts. The [3rd part][ISO-14443-3],
with the totally-not-obscure subtitle "Initialization and anticollision",
indicates that there are actually two types of NFC cards: Type A and Type B[^2].
More importantly, each type of card defines its own CRC scheme: CRC_A and CRC_B,
respectively. Finally, the [datasheet][NTAG213] for our chip states:

> NTAG213 ... [is] designed to fully comply to
> ... ISO/IEC14443 Type A ... specifications.

Great, so we need CRC_A. That's one mystery solved. To quickly verify our assumption
we can issue the `GET_CFG` command and see whether we get a NAK back.

## The authentic experience

The challenge description gives a partial message issued to the NFC device:
`1BXXXXBEAF4930`. Looking at the datasheet, we learn that this is the `PWD_AUTH`
command, which accepts a 4-byte password, and if the password is correct -
grants the host access to a protected memory area.

The datasheet also states that the protected area is defined in the `AUTH0`
configuration byte, which according to chapters 8.5 and 8.5.7 is located inside `CFG0`.
How nice, then, that the new `GET_CFG` command gives us the value of `CFG0` :).

It's a safe bet, then, that the flag is located inside the protected area.
We also note that the `READ` command returns 16 bytes of data, which is coincidentally
the size of the flag.

Great, so now we just need the password. We already know its last 2 bytes (`BE AF`)
and the CRC for the complete authentication command (`49 30`), so it's only a matter
of bruteforcing the first 2 bytes.

![NFC challenge flag retrieval (redacted)](/img/nfc_flag.png)

`FIN`


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://archive.org/download/shabak-challenge-2021/shabak-challenge-2021.zip/
    "NFC challenge files"

[NTAG213]: https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
    "NTAG213 datasheet"

[StackOverflow]: https://stackoverflow.com/a/48705557/851560
    "ISO/IEC 14443a CRC Calcuation - Stack Overflow"

[libnfc]: https://github.com/nfc-tools/libnfc/blob/bf31594410e18b7761d5536d692ea6762871e833/libnfc/iso14443-subr.c
    "libnfc CRC calculation"

[standard-search]: https://duckduckgo.com/?q=ISO%2FIEC+14443+download
    "DuckDuckGo search for the ISO/IEC 14443 standard"

[ISO-14443-2]: http://emutag.com/iso/14443-2.pdf
    "ISO/IEC 14443-2 Radio frequency power and signal interface"

[ISO-14443-3]: http://emutag.com/iso/14443-3.pdf
    "ISO/IEC 14443-3 Initialization and anticollision"

[^1]: We're not looking for easy ways.

[^2]: The types are apparently described in [ISO/IEC 14443-2][ISO-14443-2],
      but that's unimportant for our purposes.
