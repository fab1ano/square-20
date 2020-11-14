#!/usr/bin/env python3
"""Script for hosting a binary on a port."""
import signal
import subprocess
import threading

PRELOAD = 'libc.so.6'
LD = 'ld-linux-x86-64.so.2'
BINARY = 'jimi-jamming'

PORT = 2222
PORT_DBG = 2223
PORT_DBG_GDB = 2224

# Hint: You might want add --no-disable-randomization as parameter for gdbserver
# Hint: You might want to add -s as parameter for socat


def run_process(cmd):
    """Runs a socat instance repeatedly."""
    while True:
        proc = subprocess.Popen(cmd)
        proc.wait()
        if proc.returncode == 130:
            break
        print(f"socat died. Restarting. (Exit code: {proc.returncode})")


def main():
    """Starts two socat instances for hosting the binary."""

    print(f'Staring binary <{BINARY}>.')
    print('Use ^C for termination.')

    socat = 'socat'

    socat_config = f'tcp-l:{PORT},fork,reuseaddr'
    socat_config_dbg = f'tcp-l:{PORT_DBG},fork,reuseaddr'

    if LD:
        socat_exec = f'./{LD} ./{BINARY}'
        socat_exec_dbg = f'./{LD} ./{BINARY}'
    else:
        socat_exec = f'./{BINARY}'
        socat_exec_dbg = f'./{BINARY}'

    if PRELOAD:
        socat_exec = f'EXEC:env LD_PRELOAD="./{PRELOAD}" {socat_exec}'
        socat_exec_dbg = f'EXEC:"stdbuf -o0 gdbserver --wrapper env \'LD_PRELOAD=./{PRELOAD}\' -- :{PORT_DBG_GDB} {socat_exec_dbg}"'
    else:
        socat_exec = f'EXEC:"stdbuf -o0 {socat_exec}"'
        socat_exec_dbg = f'EXEC:"gdbserver :{PORT_DBG_GDB} {socat_exec_dbg}"'


    cmd = [socat, socat_config, socat_exec]
    cmd_dbg = [socat, socat_config_dbg, socat_exec_dbg]

    thread = threading.Thread(target=run_process, args=(cmd,))
    thread_dbg = threading.Thread(target=run_process, args=(cmd_dbg,))

    thread.start()
    thread_dbg.start()

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    thread.join()
    thread_dbg.join()
    print('\nShutting down.')


if __name__ == '__main__':

    main()
