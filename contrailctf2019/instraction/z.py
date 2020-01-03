from z3 import *

x = BitVec('x', 32)
y = BitVec('y', 32)
s = Solver()
# s.add((x - (0x3d6*0x3fb1d))^0x24232221==0) 
s.add(((x+(33 * 0x123456 - 20*0x112233 - 14*0x654321))^0x7818f5b8) ==0)

if s.check() == sat:
   print s.model()

