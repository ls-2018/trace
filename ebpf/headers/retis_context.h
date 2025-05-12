#ifndef __CORE_PROBE_KERNEL_BPF_RETIS_CONTEXT__
#define __CORE_PROBE_KERNEL_BPF_RETIS_CONTEXT__

#include <common_defs.h>
#include <compat.h>

enum kernel_probe_type {
    KERNEL_PROBE_KPROBE = 0,
    KERNEL_PROBE_KRETPROBE = 1,
    KERNEL_PROBE_TRACEPOINT = 2,
};

/**
 * 每个探测参数的偏移量。值为 -1 表示该参数不可用。请尝试重新使用目标对象名称。
 * 跳过默认特征实现：
 *
 * <div rustbindgen nodefault></div>
 */
struct retis_probe_offsets {
    s8 sk_buff;         // 表示内核中的 struct sk_buff 结构体的偏移
    s8 skb_drop_reason; // 表示内核中网络包被丢弃时记录原因字段的偏移
    s8 net_device;      // 对应 struct net_device，表示网络设备的数据结构偏移。
    s8 net;             // 表示网络命名空间（struct net）的偏移。
    s8 nft_pktinfo;     // 表示 Netfilter 子系统中 nft_pktinfo 结构体的偏移。
    s8 nft_traceinfo;   // 表示 Netfilter 跟踪信息结构体 nft_traceinfo 的偏移。
};

enum {
    REG_MAX = 11,                    // fexit（函数退出）探测点时，表示最多可以追踪的参数数量
    EXT_REG_SKB,                     // 这是第一个“扩展寄存器”，用于保存结构体 sk_buff（即网络包）指针或其相关数据。
    __EXT_REG_END,                   // 13
    EXT_REG_MAX = __EXT_REG_END - 1, // 12
};

// 通用上下文: 统一表示寄存器内容的结构体。它主要用于收集和传递函数调用时的参数信息，便于在不同类型的探针中处理。
struct retis_regs {
    u64 reg[EXT_REG_MAX + 1]; // ToDo 存储的应该是地址
    u64 ret;                  // 存储被探测函数的返回值
    u32 num;                  // 当前收集了多少个非扩展寄存器
};

// 用于抽象不同类型的 probe 在处理数据时的差异，使得用户可以通过统一的接口访问参数、偏移、返回值、时间戳等信息
struct retis_context {
    enum kernel_probe_type probe_type;
    u64 timestamp;                      // 探针触发时的时间戳
    u64 ksym;                           // 触发探针的符号地址
    struct retis_probe_offsets offsets; // 相关内核结构体字段的偏移信息;用于在不同内核版本中动态解析结构体字段，防止字段偏移变化导致的问题。
    struct retis_regs regs;             // 用来访问函数参数（包括扩展参数）和返回值。
    void *orig_ctx;                     // 指向原始上下文结构（比如 struct pt_regs *、struct xdp_md * 等）
    u32 filters_ret;                    // 用于记录匹配成功的过滤器标识（一个按位图）。如果某个 bit 被置为 1，表示对应的 filter 成功匹配当前上下文。
};

// 用于通过通用上下文获取函数参数参数值的辅助函数
#define retis_get_param(ctx, offset, type) (type)(((offset) >= 0 && (offset) <= EXT_REG_MAX && ((offset) > REG_MAX || (offset) < ctx->regs.num)) ? ctx->regs.reg[offset] : 0)

#define retis_offset_valid(offset) (offset >= 0)

#define retis_arg_valid(ctx, name) retis_offset_valid(ctx->offsets.name)

#define RETIS_GET(ctx, name, type) (retis_arg_valid(ctx, name) ? retis_get_param(ctx, ctx->offsets.name, type) : 0)

#define RETIS_HOOK_GET(ctx, offsets, name, type) (retis_offset_valid(offsets.name) ? retis_get_param(ctx, offsets.name, type) : 0)

#define retis_get_sk_buff(ctx) RETIS_GET(ctx, sk_buff, struct sk_buff *)
#define retis_get_skb_drop_reason(ctx) RETIS_GET(ctx, skb_drop_reason, enum skb_drop_reason)
#define retis_get_net_device(ctx) RETIS_GET(ctx, net_device, struct net_device *)
#define retis_get_net(ctx) RETIS_GET(ctx, net, struct net *)
#define retis_get_nft_pktinfo(ctx) RETIS_GET(ctx, nft_pktinfo, struct nft_pktinfo *)
#define retis_get_nft_traceinfo(ctx) RETIS_GET(ctx, nft_traceinfo, struct nft_traceinfo *)

/* Extended register helpers */
static __always_inline void retis_set_ext_sk_buff(struct retis_context *ctx, struct sk_buff *skb) {
    ctx->regs.reg[EXT_REG_SKB] = (u64)(skb);
    ctx->offsets.sk_buff = EXT_REG_SKB;
}

#endif /* __CORE_PROBE_KERNEL_BPF_RETIS_CONTEXT__ */
