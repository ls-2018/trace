#ifndef __CORE_PROBE_KERNEL_BPF_HELPERS__
#define __CORE_PROBE_KERNEL_BPF_HELPERS__

#include <bpf/bpf_tracing.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#    define BUILD_BUG_ON(cond) _Static_assert(!(cond), "BUILD_BUG_ON failed " #cond)
#else
#    define BUILD_BUG_ON(cond)
#endif

enum bpf_func_id___x { BPF_FUNC_get_func_ip___5_15_0 = 42 };

/*
 * 以下辅助函数用于在 kprobes 中获取函数的指令地址（IP）。
 *
 * 获取函数 IP 的正确方法是使用 bpf_get_func_ip，该函数在 Linux v5.15 中引入。
 * 如果运行在更旧的内核上，我们可以获取当前 IP 并手动计算上一个 IP。但是当启用了
 * CONFIG_X86_KERNEL_IBT=y 时，间接调用的落地点和以前的落地点将包含一个额外的
 * endbr 或 nop4 指令，使得函数 IP 多偏移了 4 个字节；
 * 在这种情况下，唯一能够正确获取函数 IP 的方法也是使用 bpf_get_func_ip。
 *
 * 然而，bpf_get_func_ip 的支持、CONFIG_X86_KERNEL_IBT 选项及其在 bpf_get_func_ip
 * 中的处理，是在不同的提交中实现的，合并进了不同的内核版本，并且这些提交之间没有 Fixes 标签。
 * 因此可能会出现一种情况，即启用了 CONFIG_X86_KERNEL_IBT=y，但 bpf_get_func_ip 并不支持它。
 * 我们的策略是：如果 bpf_get_func_ip 可用，就始终使用它；否则就使用手动计算的方法，
 * 以便某些稳定版/下游内核仍能正常工作。除此之外我们也无能为力，并且在启用了
 * CONFIG_X86_KERNEL_IBT=y 但 bpf_get_func_ip 不支持的某些内核上可能无法工作。
 * 希望这种情况比较少见，并且随着时间推移会变得越来越罕见。
 */
static __always_inline u64 kprobe_get_func_ip(struct pt_regs *ctx) {
    if (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_get_func_ip___5_15_0))
        return bpf_get_func_ip(ctx);
    else
#ifdef __TARGET_ARCH_x86
        return PT_REGS_IP(ctx) - sizeof(kprobe_opcode_t);
#else
        return PT_REGS_IP(ctx);
#endif
}

/* 如何判断 skb 中各类 offset（如 MAC、network、transport）是否“有效”。
 *
 * 其逻辑如下：
 * - 大多数 offset 可以通过特殊值 ~0U（即全1，例如 0xFFFFFFFF）来表示“无效”。
 * - 某些 offset 初始值可能为 0，但这时候 0 并不表示有效值，而是“尚未设置”。
 * - 所有 offset 都可以通过 skb->data - skb->head（也就是 headroom）重设，这种方式通常是合法的且可用来设置 offset。
 *
 * is_<offset>_valid 这类函数只检查 offset 本身是否合法（比如不等于 ~0U），不会检查这个 offset 实际是否指向有效数据。
 */
#define IS_UNSET(x) ((x) == (typeof(x))~0U)       // 判断变量 x 是否等于它所属类型的“全1”值（即所有位都为1）
#define IS_RESET(x, headroom) ((x) == (headroom)) // 判断某个偏移量 x 是否被重置为一个特定值 headroom

static __always_inline bool is_mac_valid(u16 mac) {
    // 只需检查 MAC 偏移量是否已设置，因为它是偏移量中的第一个，可能等于 0。
    return !IS_UNSET(mac);
}
static __always_inline bool is_network_valid(u16 network) {
    return network && !IS_UNSET(network);
}
#define is_transport_valid is_network_valid

static __always_inline bool is_mac_data_valid(const struct sk_buff *skb) {
    const u16 mac = BPF_CORE_READ(skb, mac_header);         // 以太网头
    const u16 network = BPF_CORE_READ(skb, network_header); // IP 头
    // MAC offset 有效，并且 不是以下特殊情况：网络 offset 也有效、但它和 MAC offset 完全一样、而且 MAC 长度为 0。
    // 这三者同时成立，说明 MAC 层信息其实是缺失的（mac == network 且 mac_len == 0），所以不能算作“有效 MAC 数据
    return is_mac_valid(mac) && !(is_network_valid(network) && network == mac && BPF_CORE_READ(skb, mac_len) == 0);
    // 重点场景：为何需要这一判断？
    //    有时 MAC 信息并不在 skb 中（如某些封装类型），内核会设置：
    //    mac_header == network_header
    //    mac_len == 0
    //    虽然 mac_header 值本身看起来合法（非 ~0U），但它其实根本没指向 MAC 层头部 —— 因此不能用。
}

static __always_inline bool is_network_data_valid(const struct sk_buff *skb) {
    const u16 mac = BPF_CORE_READ(skb, mac_header);
    const u16 network = BPF_CORE_READ(skb, network_header);

    return is_network_valid(network) && !(is_mac_valid(mac) && mac == network && BPF_CORE_READ(skb, mac_len) != 0);
}

static __always_inline bool is_transport_data_valid(struct sk_buff *skb) {
    const u16 network = BPF_CORE_READ(skb, network_header);
    const u16 transport = BPF_CORE_READ(skb, transport_header);

    return is_transport_valid(transport) && !(is_network_valid(network) && network == transport);
}

#endif /* __CORE_PROBE_KERNEL_BPF_HELPERS__ */
