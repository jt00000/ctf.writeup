# hadvm (3kCTF2021 / pwn)
I wrote 1 pwn task "handvm" for 3kCTF2021 and this is writeup.

## Exploit Summery
- Leak libc address from GOT with push operation which accepts negative index value.
- Edit check address table with pop operation which accepts index value 9 (= address for range check).
- Write system to `__free_hook`.
