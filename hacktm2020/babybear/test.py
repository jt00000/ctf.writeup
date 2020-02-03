from pwn import *

def load(): 
    global buf
    global text
    global pointer
    buf = int(text[pointer])
    print "buffer:", buf, "(", hex(pointer), ")"
    pointer += 1 

def ext(n):
    global ans

    print "-------------------print: ", n
    ans.append(str(n))
    if len(ans) == 0x2e:
        print "".join(ans)
        exit()

def f_104():#
    global buf
    print "104"
    ext(1)
    if buf == 1:
        f_35c()
    load()
    if buf == 0:
        f_461()
    f_35c()

def f_346():#
    global buf
    print "346"
    ext(1)
    load()
    if buf == 0:
        f_3f3() 
    else:
        f_457() 


def f_35c():
    global buf
    print "35c"
    load()
    if buf == 0:
        f_3cd()
    else:
        f_346() 

def f_370():
    global buf
    print "370"
    ext(0)
    load()
    if buf == 0:
        f_37e() 
    else:
        f_3f3()

def f_37e():
    global buf
    print "37e"
    load()
    if buf == 0:
        f_478() 
    else:
        f_394()

def f_394():#
    global buf
    print "394"
    load()
    if buf == 0:
        f_478() 
    else:
        f_3a3()

def f_3a3():#
    global buf
    print "3a3"
    ext(0)
    load()
    if buf == 0:
        f_35c()
    else:
        f_3b3()

def f_3b3():#
    global buf
    print "3b3"
    ext(0)
    load()
    if buf == 0:
        f_35c() 
    else:
        f_3c7()
def f_3c7():#
    global buf
    print "3c7"
    load()
    f_104()

def f_3cd():
    global buf
    print "3cd"
    ext(0)
    load()
    if buf == 1:
        f_370() 
    else:
        load()
        if buf == 0:
            f_461()
        else:
            f_37e()

def f_3ed():
    global buf
    print "3ed"
    # pop rdx
    f_37e()


def f_3f3():
    global buf
    print "3f3"
    load() 
    ext(1)
    f_41d()

def f_41d():
    global buf
    print "41d"
    if buf == 0:
        f_3ed() 
    else:
        f_3a3()

def f_442():
    global buf
    print "442"
    load()
    if buf == 0:
        f_3c7() 
    else:
        f_3b3()

def f_457():
    global buf
    print "457"
    load()
    f_41d()

def f_461():
    global buf
    print "461"
    ext(0)
    load()
    if buf == 0:
        f_442() 
    else:
        f_478()

def f_478():
    global buf
    print "478"
    ext(1)
    load()
    if buf == 0:
        f_442()
    else:
        f_3b3()

text = ""
pointer = 0
ans = []
buf = "" 

# raw = "A" *0x8+'\n'
# raw = p64(0x5555555555555555)
# raw = "\x0c\x06\x83\xc1\x60\x30\x18\xec\xde\x7b\xef\xbd\xf7\x5e"
raw = "\xd1\xab\x88\x91\xc7\xdd\x63\xb1\x18\x59\x11\x0f"
for x in raw:
    temp = ""
    for i in range(8):
        temp += str((ord(x) >> i) & 1)
    text += temp
text = text.ljust(0x2e*8, '0')
print text

f_35c()

