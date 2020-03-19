def show_grid():
    for row in grid:
        print row

'''
# encode
grid = [[0 for _ in range(8)] for _ in range(8)]
inp = "A"*0x20
inp = "AB" *0x10
assert(len(inp) == 0x20)

cnt = 0
for c in inp:
    bits = ord(c)
    for i in range(8):
        grid[i][(i+cnt) % 8] += ((bits >> i) & 1)  << (cnt/8)
    cnt += 1
    show_grid()
    print "----"

show_grid()
'''

out = ["CCHJEHMK", "CFKJCEOL", "FOJLMOJJ", "BDN@H@BA", "ODMJHFCJ", "MOOKMOOO", "OOAOFOGI", "@@@@@@@@"]

grid = [[ord(s)-0x40 for s in t] for t in out]
show_grid()

# decode
ans = ''
cnt = 0
for i in range(0x20):
    temp = ''
    for j in range(8):
        if grid[j][(j+cnt)%8] & (1 << (cnt/8)) != 0: 
            temp += '1'
        else:
            temp += '0'
    ans += chr(int(temp[::-1], 2))
    cnt += 1

print ans

