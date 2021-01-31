---
title: "Shabak Challenge 2021: ForceCoin"
date: 2021-01-31
---

This is part of my series of writeups on the Shabak 2021 CTF challenges.
See the complete collection [here][TOC].

## Introduction

The [challenge][Challenge] description reads:

> Our agent from the field has obtained a few files related to a program that is used
> by a terrorist organization!
>
> This zip contains the program and a db file.
>
> We need your help parsing the db!
>
> Give it your best, we heard that they use it and that it might contain some
> intresting information for you!
>
> Good Luck !!

We are presented with two encrypted files - a database and a DLL - and one program.
There must be a a clue to the encryption inside the program, so let's dive in.

## When once isn't enough

The program greets us with the following screen:

![PIN entry screen](/img/force-coin-pin.png)

Presumably, we'll have to figure out the PIN. But first, we need to determine what
we're dealing with. Throwing the EXE into [CFF Explorer][CFF] reveals that it is
a .NET executable:

![ForceCoin CFF Explorer output](/img/force-coin-cff.png)

Great, so unless the thing is obfuscated, this is going to be a breeze! Let's throw
it into [dotPeek][dotPeek] and see what we can learn.

Firstly, the code is not obfuscated, which is a relief. Secondly, there is a `PinForm`
class which looks promising. Specifically, it has a method called
`buttonCheckPin_Click`:

```c#
private void buttonCheckPin_Click(object sender, EventArgs e)
{
  string text = this.richTextBoxPinCode.Text;
  if (text.Length != 4)
  {
    this.richTextBoxPinCode.Text = "";
  }
  else
  {
    try
    {
      string input = text;
      string str = text;
      for (int index = 0; index < 10; ++index)
      {
        input = this.DoMD5(input);
        str = this.DoMD5(str);
      }
      for (int index = 0; index < 10; ++index)
        input = this.DoMD5(input);
      if ("2D3114BCC2E5C58BBAC77F04237723D9" == input)
      {
        byte[] byteArray = PinForm.StringToByteArray(str);
        this.DecryptFile(byteArray, "ForceCoinTransactionSigner.dll.enc", "ForceCoinTransactionSigner.dll");
        this.DecryptFile(byteArray, "db.txt.enc", "db.txt");
        AppForm appForm = new AppForm();
        this.Hide();
        int num = (int) appForm.ShowDialog();
        this.Close();
      }
    }
    catch (Exception ex)
    {
    }
    this.richTextBoxPinCode.Text = "";
  }
}
```

Right, so what does this do? First, the function verifies that the length of the PIN
is indeed 4 characters. Note that there is no check that the characters are *digits*,
as hinted by the dialog box. Then, the code proceeds to repeatedly calculate the MD5
hash on the PIN, and stores the result after 10 and 20 iterations (lines 14-20).
If the hash after 20 iterations matches `2D3114BCC2E5C58BBAC77F04237723D9`,
the code uses the hash after 10 iterations as the key to decrypt both the database
and the DLL (lines 21-25).

Now, the encryption used is AES, so unless by the time you are reading this somebody
managed to break it, we'll have to bruteforce the password. Since we know the PIN
has to be typed-in by hand, and since the `DoMD5` method expects the characters to be
ASCII, we can restrict ourselves to ASCII letters, digits, punctuation, and space
(`' '`).

*Note*: the `DoMD5` method outputs the hash in *uppercase*. Make sure your bruteforce
code does as well.


## An MD5 hash a day keeps the blockchain away

Excitedly, we type the password into the dialog box. It disappers, and in its place
we observe:

![Transaction editing screen](/img/force-coin-transactions.png)

Inspecting the newly-decrypted `db.txt` file, we can see it has several records similar
to:

```
0
4
Bob -> Eve [c1d9f50f86825a1a2302ec2449c17196, c1a5298f939e87e8f962a5edfc206918]
Eve -> Bob [c1d9f50f86825a1a2302ec2449c17196, a64cf5823262686e1a28b2245be34ce0, 6b6e667a40e816c4da7bb4ab64cbb82b, 1824e8e0307cbfdd1993511ab040075c, 8b1a9953c4611296a827abf8c47804d7]
Bob -> Eve [69691c7bdcc3ce6d5d8a1361f22d04ac, 318b2739ddc2c16c97b33c9b04b79f3e, 7a065d8d264a13ab77ef872a209009f2, 687b3ed5777076a28b2406f12cff289c, e592dc10241656abaa7831a661d5dafa, d517d2874919c0197866ce46e4e6511d, 4c2a8fe7eaf24721cc7a9f0175115bd4, 866f4bc698cd86191b52d3771a0a87dc]
Eve -> Bob [b9ece18c950afbfa6b0fdbfa4ff731d3, 86a1ea3adf8fbb53eb7a9b6b6b01c020, 74d25dae65d9e1bfe851af474fba7b1f, d7663fa42334fe2bdff69b245bf44c7e, 58639358a3ceb8ad0d3d84a31c856bd0, 7dd279a773d616a6dfdcdf33ce90edf8, 6b2c32b10431a155611baecbfbc4121a, c17459f971d7fac99825f2b1a3aa68bc, b6b88c87bbe8b6367b333319fa04688a, f03b844fcfaed924f6303ba7bff8b361, 891a763ee8015542bc82c988a39a2426, ba2222570942da147f52d45f6d995836, 3de9348c1ce58fe8eb57f231fc3f639c]
```

We can also add new records to the DB, by filling out the "Sender", "Recipient", and
"What" fields in the program, pressing "Push Transaction", and then
"Sign Current Block". Playing around with the program we can observe several things:

1. The first number in each block appears to be a running index. The bottom-most block
   has index 0, the one above has index 1, and so on.
2. The second number specifies the number of transactions.
3. Then, we have the actual transactions, in the format:
   `Sender -> Recipient [hex, hex, ...]`
4. The number of hex strings in each transaction appears to be equal to the length
   of the "What" field.
6. The hex strings look like MD5 hashes, but we can't be sure about that yet.

We can't load the previous transactions from the DB, so presumably we'll have
to do some more bruteforcing. In order to do that, we need to understand how
the transactions are written into the DB, and it seems that the DLL is responsible
for this. Throwing it into our favorite decompiler, however, reveals that it was
written in C++, which promises many "fun" hours of reversing. Is there an easier way?

What happens if we place just a single letter in the "What" field? Inputting `"a"`
(the letter 'a') into the field and signing the block yields:

```
Alice -> Bob [0cc175b9c0f1b6a831c399e269772661]
```

And a quick check reveals that the hex string is the MD5 hash of `"a"`. What about
`"aa"`?

```
Alice -> Bob [0cc175b9c0f1b6a831c399e269772661, 4124bc0a9335c27f086f24ba207a4912]
```

The first string remains unchanged, but the second one is clearly *not* the MD5
hash of `"a"`. Assuming that the hashes are calculated based only on the "What" field,
perhaps this is the hash of `"aa"`? Another quick check reveals that this is so.

*Hypothesis*: given a transaction with a "What" field $s$, the $i$-th hash
              in the database is a hash of $s\[0 \dots i\]$.

This can be checked with, for example, the string `"abc"`:

```
Alice -> Bob [0cc175b9c0f1b6a831c399e269772661, 187ef4436122d1cc2f40dc2b92f0eba0, 900150983cd24fb0d6963f7d28e17f72]
```

And, indeed:

```
MD5("a")   == 0cc175b9c0f1b6a831c399e269772661
MD5("ab")  == 187ef4436122d1cc2f40dc2b92f0eba0
MD5("abc") == 900150983cd24fb0d6963f7d28e17f72
```

Armed with this knowledge, we can bruteforce the transactions already stored in the DB.
To do so, we bruteforce the first letter, then the second letter appended to the first,
and so on. And again, since the characters should be typable by hand, we can restrict
the character set as we did when bruteforcing the PIN.

In fact, this is much quicker than bruteforcing the whole "What" field at once.
With our character set[^1], bruteforcing a string of length $n$ takes in the worst
case $95^{n}$ calculations of the MD5 function. Bruteforcing letter-by-letter, however,
takes at most $95n$ calculations.

![ForceCoin challenge flag retrieval (redacted)](/img/force-coin-flag.png)

`FIN`


[TOC]: {{< ref "/blog/unseen-shield.md" >}}
    "Shabak Challenge 2021 table of contents"

[Challenge]: https://archive.org/download/shabak-challenge-2021/shabak-challenge-2021.zip/
    "ForceCoin challenge files"

[CFF]: https://ntcore.com/?page_id=388
    "CFF Explorer"

[dotPeek]: https://www.jetbrains.com/decompiler/
    "dotPeek .NET decompiler"


[^1]: `string.digits + string.ascii_letters + string.punctuation + " "` in Python.
