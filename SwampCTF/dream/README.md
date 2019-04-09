# Dream Heaps
There are 2 points in this challenge.  
## Point 1: overwrite SIZE value (for leak libc)
First, we need to know libc address with leak. We can use "read dream", if SIZE isn't 0. 

We can control SIZE value when we create 20th dream beause address of HEAP_PTRS is larger than address of SIZE.  
(see blow)   
![structure](https://github.com/jt00000/ctf.writeup/blob/master/SwampCTF/dream/Screenshot%20from%202019-04-09%2022-31-27.png)

In this case, we can get leak with:  
1. Create 19 dreams.
2. Create 20th dream with length=got['puts'].
3. Read 18th dream.


## Point 2: overwrite GOT address with care
Just overwrite got['free'] to libc.system and use "delete dream" with name "/bin/sh"
But we have to care about got['puts'] because when we overwrite got['free'], "edit dream" will add extra '\xa' to GOT table.   

This causes the program to stop working. So we use "edit dream" to edit GOT table with got ['system'] + got['puts'].  
(this will destroy ['__stack_chk_fail'] which is harmless for us.) 
![flag](https://github.com/jt00000/ctf.writeup/blob/master/SwampCTF/dream/swamp2019_dreamheaps.png)
