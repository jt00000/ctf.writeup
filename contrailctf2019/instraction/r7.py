r7 =0

r8 = 0x33766f31 
r9 = r8
r10 = 0
cnt = 0
while(1):
    r7 = r7 ^ r8
    r8 += r9
    # print r8
    if r8 & 0x80 != 0:
        break
    cnt += 1
r7 = r7 & 0xffffffff
print "r7:", hex(r7)
print cnt
r8 = 0x64
r9 = 0
r10 = 1
r11 = 3
r12 = 5
r13 = 7

while(1):
    r11 -= r10
    r12 -= r10
    r13 -= r10
    if r11 & 0xff == 0:
        r11 = 3 
        r7 += 0x123456
    if r12 & 0xff == 0:
        r12 = 5
        r7 -= 0x112233
    if r13 & 0xff == 0:
        r13 = 7
        r7 -= 0x654321
    r8 -= r10
    if r8 == 0:
        break

print hex(r7)
print hex(0x7818f5b8^r7)


# (33 * 0x123456 - 20*0x112233 - 14*0x654321)
