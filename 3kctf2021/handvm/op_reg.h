#define OP_MOV_IM	0xa0
#define OP_MOV		0xa1
#define OP_LOAD		0xa2
#define OP_STORE	0xa3
#define OP_ADD		0xa4
#define OP_SUB		0xa5
#define OP_PUSH		0xa6
#define OP_POP		0xa7
#define OP_SYSCALL	0xa8
#define OP_CMP		0xa9
#define OP_BEQ		0xaa
#define OP_BNEQ		0xab
#define CODESIZE	0x100

struct vm_info {
	unsigned long long reg[6];  // reg4: sp, reg5: ip
	unsigned long long stack_lower_limit;
	unsigned long long stack_upper_limit;
	unsigned long long bss_lower_limit;
	unsigned long long bss_upper_limit;
	char flag;
};

struct map_info {
	unsigned long long *start;
	unsigned long long size;
	struct map_info *next;
};
