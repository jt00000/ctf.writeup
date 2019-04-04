from pwn import *

TARGET = './crackme03'
HOST = '104.154.106.182'
PORT = 7777

SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

r.recvuntil('#0:') 
payload = ''
payload += 'CRACKME02'
r.sendline(payload)

r.recvuntil('#1:') 
payload = ''
payload += p32(0xdeadbeef)
r.sendline(payload)

r.recvuntil('#2:') 
payload = ''
payload += 'ZXytUb9fl78evgJy3KJN'
r.sendline(payload)

r.recvuntil('#3:') 
payload = ''
payload += '1'
r.sendline(payload)

r.recvuntil('#4:') 
payload = ''
payload += 'tmzhiamaa'
r.sendline(payload)
r.interactive()
r.close()
