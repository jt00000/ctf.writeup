#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main(){
	char buf[0x100];
	read(0, buf, 0x100);
	printf(buf);
	exit(0);
}
