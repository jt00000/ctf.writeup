keys=[[2, 3, 3, 5, 3, 3, 1, 4, 1, 1, 3, 3, 1, 2, 2, 0], [5, 1, 5, 4, 7, 3, 2, 0, 0, 1, 7, 1, 0, 6, 2, 7], [2, 6, 6, 0, 5, 6, 5, 1, 6, 4, 7, 1, 1, 7, 3, 1], [4, 3, 0, 5, 2, 0, 4, 2, 7, 7, 7, 1, 1, 1, 7, 5], [1, 0, 0, 0, 4, 5, 3, 6, 3, 4, 7, 6, 4, 0, 1, 2], [5, 5, 7, 1, 3, 1, 7, 6, 6, 3, 1, 1, 2, 4, 6, 7], [2, 6, 2, 4, 1, 6, 0, 3, 7, 0, 6, 3, 0, 6, 7, 3]]
shifts=[[0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0]]
ciphertexts=[[8, 12, 10, 7, 2, 6, 3, 2, 14, 1, 8, 4, 2, 12, 9, 15], [10, 13, 5, 2, 13, 12, 11, 5, 14, 5, 3, 12, 4, 11, 0, 9], [10, 4, 0, 3, 9, 13, 13, 2, 2, 1, 0, 4, 3, 15, 11, 12], [7, 13, 1, 13, 9, 9, 9, 10, 9, 12, 3, 0, 1, 10, 7, 12], [13, 3, 10, 6, 9, 9, 2, 13, 1, 10, 13, 0, 4, 2, 1, 0], [6, 2, 2, 2, 15, 9, 12, 4, 7, 6, 2, 15, 1, 10, 14, 7], [10, 12, 6, 14, 14, 2, 14, 12, 15, 0, 15, 0, 8, 9, 4, 2]]

randarr = [9, 10, 8, 1, 14, 3, 7, 15, 11, 12, 2, 0, 4, 5, 6, 13]

def n2b(nibble):
    out =''
    for i in range(0, len(nibble), 2):
        out += chr(nibble[i]*0x10+nibble[i+1])
    return out

def b2n(by):
    blocks = (len(by) // 8) + 1
    out = []
    tmp = []
    for b in by:
        tmp.append(b >> 4)
        tmp.append(b & 0xf)
        if len(tmp) == 0x10:
            out.append(tmp)
            tmp = []
    if tmp != []:
        while(len(tmp) < 0x10):
            tmp.append(0)
        out.append(tmp)
    return out

def shift(val, idx):
    if val & 1 == 1:
        return ((((((val >> 1) - (idx >> 1)) * 2) & 0xe) - (idx & 1)) + 1) & 0xf
    else:
        return ((idx & 1) + ((idx >> 1) + (val >> 1)) * 2) & 0xf

def invshift(shifted, idx):
    for i in range(0x10):
        ret = shift(i, idx)
        if ret & 0xf == shifted:
            return i
    assert False, "something wrong"

def get_nibble(buf, idx):
    return buf[idx]

def set_nibble(buf, idx, val):
    buf[idx] = val

def reverse(ct, karr= keys, sarr=shifts, nb=0):
    block_out = ct
    round_key = [0] * 0x10

    sboxes = []
    for i in range(0x10):
        sbox = [0] * 0x10 
        for j in range(0x10):
            sel = randarr[j] 
            val = shift(sarr[nb][i], j)
            sbox[sel] = val
        sboxes.append(sbox)

    for rnd in range(0x10):
        sbox = sboxes[0xf-rnd]
        round_key = [0] * 0x10

        for i3 in range(0x10):
            val1 = get_nibble(block_out, i3)
            val2 = sbox.index(sbox.index(val1))
            set_nibble(round_key, i3, val2)
 
        for i2 in range(0x10):
            val1 = get_nibble(karr[nb], i2)
            val2 = get_nibble(round_key, i2)
            val3 = invshift(val2, val1)
            set_nibble(round_key, i2, val3)
 
        for i1 in range(0x10):
            val1 = get_nibble(round_key, sbox[i1]) 
            set_nibble(block_out, i1, val1)

    return block_out


flag = ''
for i, c in enumerate(ciphertexts):
    flag += n2b(reverse(c, nb=i))
print(flag)
