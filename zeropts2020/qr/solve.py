f_key = open('./key')
# f_key = open('./test_key')
f_qr = open('./encrypted.qr')

qr = [] 
for row in f_qr:
    tmp = []
    for x in row[:-1]:
        tmp.append(int(x))
    qr.append(tmp)

cmd_stream = [] 
for row in f_key:
    if '#' not in row:
        continue
    cmd = row.split('#')[0]
    px = row.split(',')[0].split('(')[1]
    py = row.split(',')[1].split(')')[0]
    # print cmd, px, py, row
    cmd_stream.append((cmd, px, py))

def swap(qr, x0, y0, x1, y1):
    tmp = qr[y0][x0]
    qr[y0][x0] = qr[y1][x1]
    qr[y1][x1] = tmp

print "-BEFORE-------------"
ans = ''
for row in qr:
    for p in row:
        if p == 1:
            ans += '@@'
        else:
            ans += '  '
    ans += '\n'
print ans

print "--------------------"
print "-AFTER--------------"

for c in cmd_stream:
    # print c
    cmd = int(c[0])
    px = int(c[1])
    py = int(c[2])

    if cmd == 0:
        swap(qr, px, py, px-1, py)
            
    elif cmd == 1:
        swap(qr, px, py, px+1, py)

    elif cmd == 2: 
        swap(qr, px, py, px, py-1)

    elif cmd == 3:
        swap(qr, px, py, px, py+1)

    else:
        assert('parse error')

ans = ''
for row in qr:
    for p in row:
        if p == 1:
            ans += '@@'
        else:
            ans += '  '
    ans += '\n'

print ans
