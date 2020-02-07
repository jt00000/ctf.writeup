from pwn import *
context.log_level = 'debug'

# r = process('./twisty')

# r.recvuntil('luck!\n')
# r.recvuntil('\n')
# r.recvuntil('\n')

def get_state(r):
    row = []
    check = r.recvuntil('\n')
    if "Congratulations!!!" in check: 
        r.interactive()
    row.append(check[:-1]) 
    row.append(r.recvuntil('\n')[:-1])
    row.append(r.recvuntil('\n')[:-1])
    row.append(r.recvuntil('\n')[:-1])
    return row

def get_pos(l_state, text):
    for y in range(4):
        if text in l_state[y]:
            x = l_state[y].index(text)
            return x, y 
    assert("unknown")

def mov_row(n, di):
    if di == "r": 
        return "r" + str(n) + "r"
    else:
        return "r" + str(n) + "l"
def mov_col(n, di):
    if di == "u": 
        return "c" + str(n) + "u"
    else:
        return "c" + str(n) + "d"



def set_pos(dx, dy, sx, sy):
    ans = "" 
    if dy == 0:
        if dy == sy:
            print "same y"
            ans += mov_col(sx, "d")
            ans += set_pos(dx, dy, sx, sy+1)
            return ans
            
        xdif = dx - sx
        if xdif < 0:
            ans += mov_row(sy, "l") * abs(xdif)
        elif xdif == 0:
            pass
        else:
            ans += mov_row(sy,  "r") * abs(xdif)  
 
        ydif = dy - sy 
        if ydif < 0:
            ans += mov_col(dx, "u") * abs(ydif)
 
        else:
            assert("can't be here")
        
        return ans

    else:
        # sy < 3 or error 
        if dy == sy:
            print "same y"
            ans += mov_col(sx, "d")
            ans += mov_row(sy+1, "r")
            ans += mov_col(sx, "u")
            ans += set_pos(dx, dy, (sx+1)%4, sy+1)
            return ans

        xdif = dx - sx
        if xdif == 0:
            print "same x"
            ans += mov_row(sy, "r")
            ans += set_pos(dx, dy, (sx+1)%4, sy)
            return ans

        ydif = dy - sy 
        if ydif < 0:
            ans += mov_col(dx, "d") * abs(ydif)
        else:
            assert("can't be here")

        if xdif < 0:
            ans += mov_row(sy, "l") * abs(xdif)
        elif xdif == 0:
            assert("can't be here")
        else:
            ans += mov_row(sy,  "r") * abs(xdif)  
 
        ans += mov_col(dx, "u") * abs(ydif)
        
        return ans
            
def solve_puzzle(r):
    word = []
    for i in range(12):
        word.append(chr(i + 0x41))

    for i in range(12):
        l = get_state(r) 
        x, y = get_pos(l, word[i])
        commands = set_pos((i % 4), (i / 4), x, y) 
        r.sendlineafter('> ', commands)
        # print(word[i], commands)
        for _ in range(len(commands)/3-1):
            r.recvuntil('> ')


    # adjust "M" to (0, 3)
    l = get_state(r) 
    x, y = get_pos(l, "M")

    commands = ""
    commands += "r3l" * (x - 0)
    if commands != "":
        r.sendlineafter('> ', commands)
        for _ in range(len(commands)/3 - 1):
            r.recvuntil('> ')
        l = get_state(r) 
    

    # 6 patterns
    # MNOP -> end
    # MNPO -> slide 1
    # MONP -> slide 0
    # MOPN -> slide 2
    # MPNO -> slide 2 -> 2
    # MPON -> slide 2 -> 1
    
    # print l[3]
    commands = ""
    if l[3] == "MNPO":
        print "case1"
        commands += "c1dr3lc1ur3r"
        commands += "r3rc1dr3lc1u"
        commands += "r3l"
        
    elif l[3] == "MONP":
        print "case2"
        commands += "c0dr3lc0ur3r"
        commands += "r3rc0dr3lc0u"
        commands += "r3l"
        
    elif l[3] == "MOPN":
        print "case3"
        commands += "c2dr3lc2ur3r"
        commands += "r3rc2dr3lc2u"

    elif l[3] == "MPNO":
        print "case4"
        commands += "c2dr3lc2ur3r"
        commands += "r3rc2dr3lc2u"
    
        commands += "c2dr3lc2ur3r"
        commands += "r3rc2dr3lc2u"
    
    elif l[3] == "MPON":
        print "case5"
        commands += "c2dr3lc2ur3r"
        commands += "r3rc2dr3lc2u"
        commands += "c1dr3lc1ur3r"
        commands += "r3rc1dr3lc1u"
        commands += "r3l"
    
    else:
        assert()
    
    r.sendlineafter('> ', commands)
    r.interactive()
    
