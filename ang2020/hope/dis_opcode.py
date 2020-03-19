opcode = "62f0f7fccc04f686f0f7fc69cc02871bcc00f8fbf0f1fbf8f169cc06f9fdf5f0f3f5fdf369cc06f969ccfbf68e76f0cc1bf97769cc01f6865cf0ccfdf969f7cc03f6864ff0cc00fbf8f1f769cc02f68e1bf0ccd2f96a69ccfcf68769f0fccc0ef94fcc05f686f0f5fdf4f5f8f9f776cc01f686f0f5f7f95c"

storeVALUE = 0x46
storeCTR = 0

stack0 = []
stack1 = []
reg0 = 0
reg1 = 0

pc = 0
while(pc < len(opcode)):
    cmd = int(opcode[pc:pc+2] , 16)
    # print str(pc/2).zfill(3), hex(cmd)[2:].zfill(4), "|"
    pc += 2
    if cmd == 0x62:
        print "SEGV -> input password"
        uinp = "Ga^AHxI3MF"

    elif cmd == 0x5c:
        print "win"

    elif cmd == 0xcc:
        arg = opcode[pc:pc+2] 
        pc += 2
        print "TRAP -> mov reg1 " + arg
        reg1 = int(arg, 16)
        
    elif (cmd & 0xf0) == 0x80:
        print "ILL  -> storeCTR += reg0"
        storeCTR = 0xff & (storeCTR + reg0)
        

    elif cmd == 0x69 or cmd == 0x1b or cmd == 0x76 or cmd == 0x4f:
        print "nop"

    elif cmd == 0x77 or cmd == 0x6a:
        print "storeVALUE = uinp[storeCTR]"
        storeVALUE = ord(uinp[storeCTR])

    elif cmd == 0xf0:
        print "reg0 = uinp[storeCTR] - storeVALUE", storeCTR
        reg0 = (ord(uinp[storeCTR]) - storeVALUE) & 0xff

    elif cmd == 0xf1:
        print "reg0 = reg0 + reg1"
        reg0 = (reg0 + reg1) & 0xff

    elif cmd == 0xf2:
        print "reg0 = reg0 - reg1"
        reg0 = (reg0 - reg1) & 0xff

    elif cmd == 0xf3:
        print "reg0 = reg0 * reg1"
        reg0 = (reg0 * reg1) & 0xff

    elif cmd == 0xf4:
        print "reg0 = reg0 ^ reg1", hex(reg0), hex(reg1)
        reg0 = (reg0 ^ reg1) & 0xff

    elif cmd == 0xf5:
        print "reg1 = reg0"
        reg1 = reg0

    elif cmd == 0xf6:
        print "reg0 = reg1"
        reg0 = reg1

    elif cmd == 0xf7:
        stack1.append(reg0)
        print "push_stack1 reg0||||||||", stack1

    elif cmd == 0xf8:
        reg0 = stack1.pop(-1)
        print "pop_stack1 reg0" , hex(reg0)

    elif cmd == 0xf9:
        print "if reg0 != reg1: fail" , hex(reg0), hex(reg1)
        if reg0 != reg1:
            print "--------error here---------"

    elif cmd == 0xfa:
        print "reg0 = uinp[storeCTR]"
        reg0 = uinp[storeCTR]

    elif cmd == 0xfb:
        print "xchg reg0, reg1"
        tmp = reg0
        reg0 = reg1
        reg1 = tmp
    elif cmd == 0xfc:
        print "push_stack0 reg0" 
        stack0.append(reg0)
        
    elif cmd == 0xfd:
        reg0 = stack0.pop(-1)
        print "pop_stack reg0" , hex(reg0)

    else:
        print "unknown ", hex(cmd)
