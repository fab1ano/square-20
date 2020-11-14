jimi-jam
========

This challenge was part of Square CTF 2020.

Challenge description:
```
I'm stuck in Jimi Jam jail
:( Can you let me out?
nc challenges.2020.squarectf.com 9000
```

* Points: 150
* Topics: pwn
* Given files: `jimi-jam`, `libc.so.6`

## Approach
Let's first check the mitigations techniques:
```bash
$ checksec jimi-jam
[*] './jimi-jam'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
It's not only a PIE with NX bit enabled, but also fully relro!
However, there are no stack canaries .. Maybe a stack overflow?

Now, connect to the challenge:
```bash
$ nc challenges.2020.squarectf.com 9000
Hey there jimi jammer! Welcome to the jimmi jammiest jammerino!
The tour center is right here! 0x562e82915060
Hey there! You're now in JIMI JAM JAIL

```

Great! Seems like the challenges gives us a leak.
Opening the binary in a decompiler reveals that this is the address of a 0x2000 bytes buffer (`ROPJAIL`) in the `.bss` segment.
Also, that buffer get's initialized with some pseudo random data:
```
int init_jail() {
  int i; // [rsp+Ch] [rbp-4h]

  srand(0x539u);
  for (i = 0; i <= 0x1FFF; i += 4)
    ROPJAIL[i] = rand();
  return mprotect(ROPJAIL, 0x2000uLL, 5);
}
```

However, the binary does not only initialize the buffer and print the leak, but also reads 0x40 bytes from the user into a 8 byte buffer on the stack (function `vuln()`).
Thus, I didn't look at the `ROPJAIL` buffer but instead sent two ropchains.

**First Ropchain:**
The first ropchain leaks the address of `libc`.
One can easily leak the address of `puts` by leaking the entry in the `.plt.sec` section of `jimi-jam` and jump back to `vuln()`.
Thus, the ropchain contains four entries:

1. The address of a `pop rdi` gadget (0x13a3)
2. The address of `puts` in the `.got` segment (can be any entry from the `.got`)
3. The address of `puts` in the `.plt.sec` segment
4. The address of `vuln` such that we can execute another ropchain

With this ropchain we get the address of `libc`.

**Second Ropchain:**
The second ropchain contains a one_gadget and sets the required registers beforehand.
We go for the following one_gadget:
```
0xe6e79 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

Thus, we need to set `rsi` and `rdx`.
Fortunately, the `libc` provides rop gadgets for that:
```
0x162866:  pop rdx; pop rbx; ret;
0x027529:  pop rsi; ret;
```

So, we just use these gadgets to set the registers to 0 and then jump to the one_gadget.
This leads to code execution!

## Exploit
You can find the exploit in [`x.py`](./x.py).

Just run it:
```bash
$ ./x.py remote
[*] './jimi-jam'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] './libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenges.2020.squarectf.com on port 9000: Done
[*] Binary @ address 0x555b429d5000
[*] Sending first ropchain (leak libc address)
[*] Libc @ address 0x7fbbbd7e8000
[*] Sending second ropchain (RCE)
[*] Switching to interactive mode
$ cat flag.txt
flag{do_you_like_ropping}
$
```
