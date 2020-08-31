with open('./bytes') as f:
    raw = f.read()

code = []
for byte in raw.split(' '):
    code.append(int(byte, 16))

# print hex(print_ip), code

def get_byte(addr_from):
    return code[addr_from]

def get_word(addr_from):
    return code[addr_from] | code[addr_from+1] << 8

def get_dword(addr_from):
    return code[addr_from] | code[addr_from+1] << 8 | code[addr_from+2] << 16 | code[addr_from+3] << 24

def get_qword(addr_from):
    return code[addr_from] | code[addr_from+1] << 8 | code[addr_from+2] << 16 | code[addr_from+3] << 24 | code[addr_from+4] << 32 | code[addr_from+5] << 40 | code[addr_from+6] << 48 | code[addr_from+7] << 56

ip = 0
r0 = 0
r1 = 0
r2 = 0

while(1):
    inst = code[ip]
    print_ip = ip+0x20+3
    ip += 1
    if inst == 0x10:
        print hex(print_ip), "mov r0, sp"
    elif inst == 0x11:
        value = get_qword(ip)
        r0 = value
        print hex(print_ip), "mov r0, %x" % value
        ip += 8
    elif inst == 0x12:
        value = get_qword(ip)
        r1 = value
        print hex(print_ip), "mov r1, %x" % value
        ip += 8
    elif inst == 0x13:
        value = get_qword(ip)
        r2 = value
        print hex(print_ip), "mov r2, %x" % value
        ip += 8
    elif inst == 0x20:
        value = get_qword(ip)
        print hex(print_ip), "mov r0, buf+%x" % value
        ip += 8
    elif inst == 0x21:
        value = get_qword(ip)
        print hex(print_ip), "mov r0, qwptr [buf+%x]" % value
        ip += 8
    elif inst == 0x22:
        value = get_qword(ip)
        print hex(print_ip), "mov r1, qwptr [buf+%x]" % value
        ip += 8
    elif inst == 0x23:
        value = get_qword(ip)
        print hex(print_ip), "mov r2, qwptr [buf+%x]" % value
        ip += 8
    elif inst == 0x33:
        value = get_qword(ip)
        print hex(print_ip), "mov qwptr [buf+%x], r0" % value
        ip += 8
    elif inst == 0x34:
        value = get_qword(ip)
        print hex(print_ip), "mov qwptr [buf+%x], r1" % value
        ip += 8
    elif inst == 0x35:
        value = get_qword(ip)
        print hex(print_ip), "mov qwptr [buf+%x], r2" % value
        ip += 8
    elif inst == 0x44:
        print hex(print_ip), "push r0"
    elif inst == 0x45:
        print hex(print_ip), "push r1"
    elif inst == 0x46:
        print hex(print_ip), "push r2"
    elif inst == 0x51:
        print hex(print_ip), "pop r0"
    elif inst == 0x52:
        print hex(print_ip), "pop r1"
    elif inst == 0x53:
        print hex(print_ip), "pop r2"
    elif inst == 0x61:
        value = get_qword(ip)
        print hex(print_ip), "add r0, %x" % value
        ip += 8
    elif inst == 0x62:
        value = get_qword(ip)
        print hex(print_ip), "add r1, %x" % value
        ip += 8
    elif inst == 0x63:
        value = get_qword(ip)
        print hex(print_ip), "add r2, %x" % value
        ip += 8
    elif inst == 0x64:
        value = get_qword(ip)
        print hex(print_ip), "sub r0, %x" % value
        ip += 8
    elif inst == 0x65:
        value = get_qword(ip)
        print hex(print_ip), "sub r1, %x" % value
        ip += 8
    elif inst == 0x66:
        value = get_qword(ip)
        print hex(print_ip), "sub r2, %x" % value
        ip += 8
    elif inst == 0x67:
        value = get_qword(ip)
        print hex(print_ip), "mul r0, %x" % value
        ip += 8
    elif inst == 0x68:
        value = get_qword(ip)
        print hex(print_ip), "mul r1, %x" % value
        ip += 8
    elif inst == 0x69:
        value = get_qword(ip)
        print hex(print_ip), "mul r2, %x" % value
        ip += 8
    elif inst == 0x6a:
        value = get_qword(ip)
        print hex(print_ip), "xor r0, %x" % value
        ip += 8
    elif inst == 0x6b:
        value = get_qword(ip)
        print hex(print_ip), "xor r0, %x" % value
        ip += 8
    elif inst == 0x6c:
        value = get_qword(ip)
        print hex(print_ip), "xor r0, %x" % value
        ip += 8
    elif inst == 0x6d:
        print hex(print_ip), "xor r0, r0"
        r0 = 0
    elif inst == 0x6e:
        print hex(print_ip), "xor r1, r1"
        r1 = 0
    elif inst == 0x6f:
        print hex(print_ip), "xor r2, r2"
        r2 = 0
    elif inst == 0x7e:
        value = get_word(ip)
        ip += 2
        ip += value
        print hex(print_ip), "jmp %x" % value 

    elif inst == 0x7f:
        print hex(print_ip), "mov ip, r0" # ??? 
        
    elif inst == 0x80:
        print hex(print_ip), "call r0" 
    elif inst == 0x81:
        value = get_qword(ip)
        print hex(print_ip), "add sp %x" % (value & 0xfffff000)
        ip += 8
    elif inst == 0x82:
        value = get_qword(ip)
        print hex(print_ip), "sub sp %x" % (value & 0xfffff000)
        ip += 8
    elif inst == 0x88:
        value = get_word(ip)
        print hex(print_ip), "call ip+%x" % value
        ip += 2
        ip = (value + ip) & 0xffff

    elif inst == 0x8f:
        value = get_byte(ip)
        if value == 0:
            print hex(print_ip), "read(%x, %x, %x)" % (r0, r1, r2)
        elif value == 1:
            print hex(print_ip), "write(%x, %x, %x)" % (r0, r1, r2)
        elif value == 2:
            print hex(print_ip), "puts(%x)" % r0
        elif value == 3:
            print hex(print_ip), "free(%x)" % r0
        else:
            print hex(print_ip), "0x8f: invalid number"
            exit()
        ip += 1
    elif inst == 0x90:
        print hex(print_ip), "ret"
        # this is not proper exit.. (but it's enough to analyze.)
        exit()

    elif inst == 0xff:
        print hex(print_ip), "exit"
        exit()
        
    else: 
        print hex(print_ip), "disasm error: %x" % inst
        exit()


