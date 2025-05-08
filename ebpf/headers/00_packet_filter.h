#ifndef __CORE_FILTERS_PACKETS_PACKET_FILTER__
#define __CORE_FILTERS_PACKETS_PACKET_FILTER__

#include <00_common_defs.h>

struct retis_packet_filter_ctx {
    /* Input */
    char *data;       // 输入：指向数据包 MAC 头部起始位置的指针
    unsigned int len; // 输入：数据的线性长度（即可以直接访问的连续内存长度）

    /* Output */
    unsigned int ret; // 输出：匹配结果（为0表示未命中任何过滤规则）
} __binding;

// 我们需要在这里使用 #define，因为 __FILTER_MAX_INSNS 会被 预处理器（pre-processor） 使用，而预处理器还不认识 enum（枚举）。
#define __FILTER_MAX_INSNS 4096
BINDING_DEF(FILTER_MAX_INSNS, __FILTER_MAX_INSNS)

#define __s(v) #v
#define s(v) __s(v)

BINDING_DEF(STACK_RESERVED, 8)
BINDING_DEF(SCRATCH_MEM_SIZE, 4)

/* 8 bytes for probe_read_kernel() outcome plus 16 * 4 scratch
 * memory locations for cbpf filters. Aligned to u64 boundary.
 */
BINDING_DEF(SCRATCH_MEM_START, 16 * SCRATCH_MEM_SIZE + STACK_RESERVED)

#define l2 0xdeadbeef
#define l3 0xdeadc0de

enum filter_type {
    L2 = l2,
    L3 = l3,
} __binding;

#endif
