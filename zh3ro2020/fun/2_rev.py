with open('./edit_dis') as f:
    dis = f.read().split('\n')

reg6040 = [(0,0x32)]
for i, row in enumerate(dis):
    if "6040" in row:
        if "mov" not in dis[i+1]:
            value = int(dis[i+1].split(' ')[-1].split(',')[1], 16)
            addr = int(dis[i+1].split(' ')[4][:4], 16)
            # print hex(addr), hex(value)
            # print dis[i+1]
            if "sub" in dis[i+1]:
                reg6040.append((addr, reg6040[-1][1]-value))
            else:
                reg6040.append((addr, reg6040[-1][1]+value))
    
            # print dis[i+1].split(' '), dis[i+1].split(' ')[-1].split(',')[1]
'''
for x in reg6040:
    print hex(x[0]), hex(x[1])
exit()
'''

def get_addr(row):
    # print "debug:", row
    addr = int(row.split(' ')[4][:4], 16)
    return addr

def get_6040_value(row):
    print "debug: ", row
    addr = get_addr(row)
    for i in reg6040[::-1]:
        if addr > i[0]:
            return i[1]
    print "ERROR in get_6040_value"
    exit()
def edit_out(array):
    name = [hex(i)[2:] for i in range(0x60, 0xa0, 4)]
    
    prev = ''
    line = ''
    for x in sorted(array): 
        # print "edit_out, debug:" ,x
        curr = x[0]
        if curr != prev:
            line += '==0)'
            print line
            line = 's.add('
        if len(x) == 3:
            line += "v["+str(x[1])+"]*"+str(x[2])+ "+"
        else:
            line += "-"+str(x[1])
        prev = curr
    line += '==0)'
    print line

cnt = 0
output = []
while(1):
    if "#" in dis[cnt] and "6040" not in dis[cnt]:
        print "MAIN: ", dis[cnt]
        addr = get_addr(dis[cnt])
        key = get_6040_value(dis[cnt])
        reg = dis[cnt].split('# ')[1][2:4]
        if "movsx" not in dis[cnt+1] and "sub" not in dis[cnt+1]: # pattern: normal (movsx is in lower side)
            subcnt = 1
            while(1):
                if "movsx" in dis[cnt-subcnt]:
                    # print dis[cnt-subcnt]
                    break
                subcnt += 1
            pos = dis[cnt-subcnt].split('rsi')[1].split(']')[0]
            if pos == '':
                pos = 0
            else: 
                pos = int(pos, 16)
            while("6040" not in dis[cnt]):
                cnt += 1
            # print "REG, POS, KEY: ", reg, pos, key
            # print hex(addr), reg, pos, key
            print reg, pos, key
            output.append((reg, pos, key))

        elif "sub" in dis[cnt+1]: #pattern: sub word
            # print dis[cnt+1]
            value = int(dis[cnt+1].split(',')[1][:6], 16)
            while("6040" not in dis[cnt]):
                cnt += 1
                if cnt == 2394:
                    print reg, value
                    output.append((reg, value))
                    edit_out(output)
                    exit()
            # print "REG, VALUE: ", reg, hex(value)
            # print hex(addr), reg, value
            print reg, value
            output.append((reg, value))

        else: # pattern: normal (movsx is in higer side)
            # print dis[cnt+1]
            pos = dis[cnt+1].split('rsi')[1].split(']')[0]
            if pos == '':
                pos = 0
            else: 
                pos = int(pos, 16)
            while("6040" not in dis[cnt]):
                cnt += 1
            # print "REG, POS, KEY: ", reg, pos, key
            # print hex(addr), reg, pos, key
            print reg, pos, key
            output.append((reg, pos, key))
        # print "--------"
    else:
        cnt += 1
    if dis[cnt] == '':
        break


