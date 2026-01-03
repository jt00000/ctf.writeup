from z3 import *

BV32 = BitVecSort(32)

STATE_VECTOR_LENGTH = 624
STATE_VECTOR_M = 397

UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff
MAG1 = 0x9908b0df

B = 0x9D2C5680
C = 0xEFC60000


def mt_init(seed):
    mt = [None] * STATE_VECTOR_LENGTH
    mt[0] = seed
    for i in range(1, STATE_VECTOR_LENGTH):
        mt[i] = (mt[i-1] * BitVecVal(6069, 32)) & 0xffffffff
    return mt


def mt_twist(mt):
    new = [None] * STATE_VECTOR_LENGTH
    for i in range(STATE_VECTOR_LENGTH):
        y = (mt[i] & UPPER_MASK) | (mt[(i+1) % STATE_VECTOR_LENGTH] & LOWER_MASK)
        mag = If((y & 1) == 1, BitVecVal(MAG1, 32), BitVecVal(0, 32))
        new[i] = mt[(i + STATE_VECTOR_M) % STATE_VECTOR_LENGTH] ^ LShR(y, 1) ^ mag
    return new


def temper(y):
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & B)
    y = y ^ ((y << 15) & C)
    y = y ^ LShR(y, 18)
    return y & 0xffffffff


def solz(target_addr):
    seed = BitVec('seed', 32)

    mt = mt_init(seed)
    mt2 = mt_twist(mt)
    out = temper(mt2[0])

    s = Solver()
    s.add(out == BitVecVal(target_addr, 32))

    # タイムアウト必須（数秒〜数十秒）
    s.set(timeout=10_000)

    if s.check() == sat:
        m = s.model()
        return m[seed].as_long()
    else:
        return None
