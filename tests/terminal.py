#!/usr/bin/env python3
# terminal.py - run slip0039 on a pseudo terminal, to test the prompts
#
# usage: tests/terminal.py LINE... -- COMMAND ARG...
#
# the lines are typed one by one, after a prompt; prints what appeared on
# the terminal, followed by "exit status N"

import os
import pty
import select
import sys
import time

def read_all(fd, timeout):
    out = b""
    while select.select([fd], [], [], timeout)[0]:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
    return out

def main(argv):
    sep = argv.index("--")
    lines, command = argv[:sep], argv[sep + 1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(command[0], command)
    out = b""
    for line in lines:
        out += read_all(fd, 0.5)
        os.write(fd, line.encode() + b"\r")
    out += read_all(fd, 5)
    _, status = os.waitpid(pid, 0)
    sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
    print("exit status %d" % os.waitstatus_to_exitcode(status))

if __name__ == "__main__":
    main(sys.argv[1:])
