from pwn import *

words = "angstromctf20"
mod = len(words)

def func1(inp): 
    assert len(inp) == 0x20 
    shalf = ''.join([inp[c] for c in range(1, len(inp), 2)])
    # print shalf
    v = [u64(shalf[i:i+8]) for i in range(0, len(shalf), 8)]
    arg0 = (v[0] ^ 0xffffffffffffffff)+1
    arg1 = v[1] ^ 0x1234567890abcdef
    # print hex(arg0), hex(arg1)
    return arg0, arg1

def func2(arg0, arg1):
    fhalf = ''.join([inp[c] for c in range(0, len(inp), 2)])
    v = [u64(fhalf[i:i+8]) for i in range(0, len(fhalf), 8)]
    n1 = v[0]
    n2 = v[1] ^ 0xffffffffffffffff 
    n3 = arg0 + 0x1337
    n4 = arg1 - 0x4242 
    return n1, n2, n3, n4

def subst(num):
    text = ''
    x = num
    while (num > 0):
        text = words[num % mod] + text
        num /= mod 
    return text

def un_subst(text):
    num = 0
    v = []
    for i in range(len(text)):
        x = words.index(text[i])
        num = num * mod + x
        v.append(x)
    return num, v

def num(v):
    ans = 0
    for i in v:
        ans = ans * mod + i
    return ans

# arg0, arg1 = func1(inp)
# n1, n2, n3, n4 = func2(arg0, arg1)

# n1, v = un_subst("artomtf2srn00tgm2f")
# print v
v = [0, 5, 4, 6, 7, 4, 10, 11, 3, 5, 1, 12, 12, 9, 2, 7, 11, 10]
n1 = (num(v))
# print hex(n1)

# n2, v = un_subst("ng0fa0mat0tmmmra0c")
# n2 = n2 ^ 0xffffffffffffffff
v = [1, 2, 12, 10, 0, 12, 7, 0, 9, 12, 4, 7, 7, 7, 5, 0, 12, 8]
n2 = (0xffffffffffffffff ^ num(v))
# print hex(n2)

# n3, v = un_subst("ngnrmcornttnsmgcgr")
v = [1, 2, 1, 5, 7, 8, 6, 5, 1, 4, 9, 1, 3, 7, 2, 8, 2, 5]
n3 = (0xffffffffffffffff ^ (num(v)-0x1338))
# print hex(n3)

# n4, v = un_subst("a0fn2rfa00tcgctaot")
# n4 = (n4 + 0x4242) ^ 0x1234567890abcdef
v = [0, 12, 10, 1, 11, 5, 10, 0, 12, 12, 4, 8, 2, 8, 4, 0, 6, 9]
n4 = (0x1234567890abcdef ^ (num(v)+0x4242))
# print hex(n4)

print hex(n1), hex(n2), hex(n3), hex(n4) 


ans = ''
text = hex(n1)[2:]
for i in range(0, len(text), 2):
    ans = chr(int(text[i:i+2], 16)) + ans
tmp = ans
ans = ''
text = hex(n2)[2:]
for i in range(0, len(text), 2):
    ans = chr(int(text[i:i+2], 16)) + ans
ans = tmp + ans
print ans


ans2 = ''
text = hex(n3)[2:]
for i in range(0, len(text), 2):
    ans2 = chr(int(text[i:i+2], 16)) + ans2
tmp = ans2
ans2 = ''
text = hex(n4)[2:]
for i in range(0, len(text), 2):
    ans2 = chr(int(text[i:i+2], 16)) + ans2
ans2 = tmp + ans2
print ans2

total = ''
for i in range(len(ans)):
    total += ans[i]
    total += ans2[i]

print total


