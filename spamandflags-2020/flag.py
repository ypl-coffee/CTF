from pwn import *

context.log_level = "DEBUG"

r = remote("35.242.182.148", 1337)

r.recvline()

with open("./replay.txt") as f:
    raw = f.readline()
    while (len(raw) > 2):
        r.send(raw)
        raw = f.readline()

r.sendline("")

r.recvall(timeout=5.0)
r.interactive()
