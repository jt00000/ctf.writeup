#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "op_reg.h"
#include <sys/mman.h>
//#define DEBUG

struct vm_info vm;
struct map_info *root;

char check_reg(unsigned char);

void op_mov_im(unsigned char n, unsigned long long value) {
	char result = 1;
	result = check_reg(n);
	if (result == 0) vm.reg[n] = value;
}

void op_mov(unsigned char dest, unsigned char src) {
	char result = 1;
	result = check_reg(dest);
	if (result == 0) {
		result = check_reg(src);
		if (result == 0) vm.reg[dest] = vm.reg[src];
	}
}

void op_load(unsigned char dest, unsigned char src) {
	char result = 1;
	result = check_reg(dest);
	if (result == 0) {
		result = check_reg(src);
		if (result == 0 && vm.reg[src] != 0) vm.reg[dest] = *(unsigned long long *)(vm.reg[src]);
	}
}

void op_store(unsigned char dest, unsigned char src) {
	char result = 1;
	result = check_reg(dest);
	unsigned long long *p = (unsigned long long *) vm.reg[dest];
	if (result == 0) {
		result = check_reg(src);
		if (result == 0) *p = (unsigned long long)vm.reg[src];
	}
}

void op_add(unsigned char dest, unsigned char src) {
	char result = 1;
	result = check_reg(dest);
	if (result == 0) {
		result = check_reg(src);
		if (result == 0) vm.reg[dest] += vm.reg[src];
	}
}

void op_sub(unsigned char dest, unsigned char src) {
	char result = 1;
	result = check_reg(dest);
	if (result == 0) {
		result = check_reg(src);
		if (result == 0) vm.reg[dest] -= vm.reg[src];
	}
}

void op_push(unsigned char n) {
	char result = 1;
	result = check_reg(n);
	if (result == 0) {
		if (vm.reg[4]+8 < vm.stack_upper_limit) {
			vm.reg[4] += 8;
			unsigned long long *p = (unsigned long long *)vm.reg[4];
			*p = vm.reg[(char)n];
		}
	}
}

void op_pop(unsigned char n) {
	char result = 1;
	result = check_reg(n);
	if (result == 0) {
		if (vm.reg[4]-8 >= vm.stack_lower_limit) {
			unsigned long long *p = (unsigned long long *)vm.reg[4];
			vm.reg[n] = *p;
			vm.reg[4] -= 8;
		}
	}
}

char check_reg(unsigned char n) {
	if (n == 4) {
#ifdef DEBUG
		puts("sp");
#endif
		return 1;
	}
	else if (n == 5) {
#ifdef DEBUG
		puts("ip");
#endif
		return 1;
	}
	return 0;
}
char check_range(unsigned long long *start, unsigned long long *end) {
	struct map_info *p;
	if (end - start > 0x400) {
		return 1;
	}
	p = root;
	while(1) {
		if ((unsigned long long)p->start <= (unsigned long long)start) break;
		if (p->next == NULL) return 1;
		p = p->next;
	}

#ifdef DEBUG
	printf("claim start: %llx, claim end: %llx\n", (unsigned long long)start, (unsigned long long)end);
	printf("p->start: %llx, p->size: %llx\n", (unsigned long long)p->start, (unsigned long long)p->size);
#endif
	if ((unsigned long long)p->start + p->size <= (unsigned long long)end) {
#ifdef DEBUG
		puts("check fail");
#endif
		return 1;
	}
	else {
#ifdef DEBUG
		puts("check success");
#endif
		return 0;
	}
}

void op_call(void) {
	char result = 1;
	unsigned long long *end = (unsigned long long *)(vm.reg[2] + vm.reg[3]);
	switch(vm.reg[0]) {
		case 0:
			result = check_range((unsigned long long *)vm.reg[2], end);
			if (result == 0) vm.reg[0] = read(vm.reg[1], (void *)vm.reg[2], vm.reg[3]);
			else vm.reg[0] = -1;
			break;
		case 1:
			result = check_range((unsigned long long *)vm.reg[2], end);
			if (result == 0) vm.reg[0] = write(vm.reg[1], (void *)vm.reg[2], vm.reg[3]);
			else vm.reg[0] = -1;
			break;
		default:
			vm.reg[0] = -1;
			break;
	}
}

void op_cmp(unsigned long long dest, unsigned long long src) {
	char result = 1;
	result = check_reg(dest);
	if (result == 0) {
		result = check_reg(src);
		if (result == 0) {
			if (vm.reg[dest] == vm.reg[src]) {
#ifdef DEBUG
				puts("equal");
#endif
				vm.flag = 1;
			}
			else {
				vm.flag = 0;
			}
		}
	}
}

unsigned long long op_jmp(unsigned long offset) {
	char result = 1;
	result = check_range((unsigned long long *) (vm.reg[5]+offset), 0);
	if (result == 0) {
		return vm.reg[5] + offset;
	}
	else {
		return vm.reg[5];
	}
}

void init_vm(unsigned long long *entry, unsigned long long *stack_top, unsigned long long *stack_bottom, unsigned long long *bss_top, unsigned long long *bss_bottom) {
	for (int i = 0; i < 4; i++) {
		vm.reg[i] = 0;
	}
	vm.reg[4] = (unsigned long long)stack_top;
	vm.reg[5] = (unsigned long long)entry;
	vm.stack_lower_limit = (unsigned long long)stack_top;
	vm.stack_upper_limit = (unsigned long long)stack_bottom;
	vm.bss_lower_limit = (unsigned long long)bss_top;
	vm.bss_upper_limit = (unsigned long long)bss_bottom;
	vm.flag = 0;
}
void deinit_vm(void) {
	for (int i = 0; i < 6; i++) {
		vm.reg[i] = 0;
	}
	vm.stack_lower_limit = 0;
	vm.stack_upper_limit = 0;
	vm.bss_lower_limit = 0;
	vm.bss_upper_limit = 0;
	vm.flag = 0;
}

void register_map_info(unsigned long long *start, unsigned long long size) {
	struct map_info *p, *tmp;
	p = malloc(sizeof(struct map_info));
	p->start = start;
	p->size = size;
	if (root == NULL) {
		root = p;
	}
	else {
		tmp = root;
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = p;
	}
}

void dump_state() {
	printf("-------------------------------------------------\n");
	printf("\t REG0:\t\t%llx\n", vm.reg[0]);
	printf("\t REG1:\t\t%llx\n", vm.reg[1]);
	printf("\t REG2:\t\t%llx\n", vm.reg[2]);
	printf("\t REG3:\t\t%llx\n", vm.reg[3]);
	printf("\t REG4(sp):\t%llx\n", vm.reg[4]);
	printf("\t REG5(ip):\t%llx\n", vm.reg[5]);
	printf("\t stack_lower:\t%llx\n", vm.stack_lower_limit);
	printf("\t stack_upper:\t%llx\n", vm.stack_upper_limit);
	printf("-------------------------------------------------\n");
}

#ifdef DEBUG
void dump_map() {
	struct map_info *p;
	p = root;
	printf("-------------------------------------------------\n");
	while(1) {
		printf("\t start:\t%16llx\t|\tend:\t%16llx\n", (unsigned long long)p->start, (unsigned long long)(p->start) + (p->size));
		if (p->next != NULL) {
			p = p->next;
		}
		else break;
	}
	printf("-------------------------------------------------\n");
}
#endif

#define WIDTH 16
void dump_code(unsigned long long *code, int length) {
	int loop = (length / WIDTH) + 1;
	unsigned char *p = (unsigned char *) code;
	printf("       ");
	for (int j = 0; j < WIDTH; j++) {
		printf("%02x ", j);
	}
	puts("\n-------------------------------------------------------");
	for (int i = 0; i < loop; i++) {
		printf("%04x | ", i);
		for (int j = 0; j < WIDTH; j++) {
			printf("%02x ", p[i*WIDTH+j]);
		}
		puts("");
	}
	puts("");
}

unsigned long long *map(unsigned long long size ,unsigned long long start) {
	unsigned long long *ret;
	if (size > 0x1000) {
		return 0;
	}
	if (start == 0) {
		ret = (unsigned long long *)malloc(size);
	}
	else {
		ret = mmap((void *)start, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	}
	memset(ret, 0, size);
	register_map_info(ret, size);
	
	return ret;
}

void init(void) {
	setvbuf(stdin,  NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	alarm(60);
}

int user_input(unsigned long long *code, unsigned long long size) {
	int ret = 1;
	puts("insert your code here ...");
	printf("> ");
	ret = read(0, code, size);
	puts("");
	if (ret < 0) {
		puts("input error!");
		exit(1);
	}
	else {
		return ret;
	}
}

void exec_vm(void) {
	unsigned char *ip = (unsigned char *) vm.reg[5];
	unsigned char op;
	unsigned char v0, v1;
	unsigned long long value;
	while(*ip != 0) {
#ifdef DEBUG
		dump_state();
		printf("ip is on %p\n", *ip);
#endif
		op = *ip++;

		if (op == OP_MOV_IM) {
			v0 = *ip++;
			value = *(unsigned long long *)ip;
			ip += 8;
#ifdef DEBUG
			printf("mov reg%d %p\n", v0, value);
#endif
			op_mov_im(v0, value);
		}
		else if (op == OP_MOV) {
			v0 = *ip++;
			v1 = *ip++;
#ifdef DEBUG
			printf("mov reg%d reg%d\n", v0, v1);
#endif
			op_mov(v0, v1);
		}
		else if (op == OP_LOAD) {
			v0 = *ip++;
			v1 = *ip++;
#ifdef DEBUG
			printf("load reg%d qword[reg%d]\n", v0, v1);
#endif
			op_load(v0, v1);
		}
		else if (op == OP_STORE) {
			v0 = *ip++;
			v1 = *ip++;
#ifdef DEBUG
			printf("store qword[reg%d] reg%d\n", v0, v1);
#endif
			op_store(v0, v1);
		}
		else if (op == OP_ADD) {
			v0 = *ip++;
			v1 = *ip++;
#ifdef DEBUG
			printf("add reg%d reg%d\n", v0, v1);
#endif
			op_add(v0, v1);
		}
		else if (op == OP_SUB) {
			v0 = *ip++;
			v1 = *ip++;
#ifdef DEBUG
			printf("sub reg%d reg%d\n", v0, v1);
#endif
			op_sub(v0, v1);
		}
		else if (op == OP_PUSH) {
			v0 = *ip++;
#ifdef DEBUG
			printf("push reg%d\n", v0);
#endif
			op_push(v0);
		}
		else if (op == OP_POP) {
			v0 = *ip++;
#ifdef DEBUG
			printf("pop reg%d\n", v0);
#endif
			op_pop(v0);
		}
		else if (op == OP_SYSCALL) {
#ifdef DEBUG
			printf("syscall\n");
#endif
			op_call();
		}
		else if (op == OP_CMP) {
#ifdef DEBUG
			printf("cmp\n");
#endif
			v0 = *ip++;
			v1 = *ip++;
			op_cmp(v0, v1);
		}
		else if (op == OP_BEQ) {
#ifdef DEBUG
			printf("beq\n");
#endif
			value = *(unsigned long long *)ip;
			ip += 8;
			if (vm.flag == 1) ip = (unsigned char *) op_jmp(value);
		}
		else if (op == OP_BNEQ) {
#ifdef DEBUG
			printf("bneq\n");
#endif
			value = *(unsigned long long *)ip;
			ip += 8;
			if (vm.flag == 0) ip = (unsigned char *) op_jmp(value);
		}
		else {
#ifdef DEBUG
			puts("no op");
#endif
		}
		vm.reg[5] = (unsigned long long) ip;
	}
}

int main(void) {
	int length = 0;
	//unsigned long long *dummy = map(0x100);
	//dump_map();
	unsigned long long *code = map(CODESIZE, 0);
	//dump_map();
	unsigned long long *bss = map(0x100, 0xdead000);
	//dump_map();
	unsigned long long *stack = map(0x100, 0);
	//dump_map();

	init();
	length = user_input(code, CODESIZE);
	dump_code(code, length);
	init_vm(code, stack, stack+(0x100/8), bss, bss+(0x100/8));
	//dump_state();

/*
	op_mov_im(0, 1);
	op_mov_im(1, 1);
	op_push(4);
	op_pop(2);
	op_mov_im(3, 0xa44434241);
	op_push(3);
	op_mov_im(3, 0xffffffffffffffff);
	dump_state();
	op_call();
*/
	//dump_state();
	puts("[ vm ] start");
	exec_vm();
	puts("[ vm ] end");
	dump_state();
	deinit_vm();
	free(code);
	free(stack);
	exit(0);
}
