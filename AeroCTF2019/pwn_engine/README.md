# Writeup
1. leak got.strcmp
2. overwrite got.exit -> sym.main (for ret2vuln)  
sendline [1]
---

3. calc libcbase from leak info
4. overwrite got.strcmp -> libc.system   
sendline [2] 
---

5. authflag 1 -> 0 (for use got.strcmp)  
sendline[3]

6. input username "/bin/sh"