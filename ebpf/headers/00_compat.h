#ifndef __CORE_PROBE_KERNEL_BPF_COMPAT__
#define __CORE_PROBE_KERNEL_BPF_COMPAT__
#include <vmlinux.h>

struct nft_rule___3_13_0 {
    u64 handle : 42;
} __attribute__((preserve_access_index));

struct nft_rule_dp___5_17_0 {
    u64 is_last : 1, handle : 42; // is_last 标志位，表示是否是当前链表或规则列表中的最后一条规则。
} __attribute__((preserve_access_index));

// /include/net/netfilter/nf_tables.h
// struct nft_traceinfo {
struct nft_traceinfo___6_3_0 {
    const struct nft_pktinfo *pkt;     // 指向当前处理的数据包信息
    const struct nft_rule_dp *rule;    // 当前匹配的规则
    const struct nft_verdict *verdict; // 当前规则的裁决（接受、丢弃、跳转等）
} __attribute__((preserve_access_index));

// /include/net/netfilter/nf_tables.h
// struct nft_rule_dp_last {
struct nft_rule_dp_last___6_4_0 {
    const struct nft_chain *chain; // 当前规则所属的链
} __attribute__((preserve_access_index));

// /tools/include/uapi/linux/bpf.h
// struct __sk_buff {
struct sk_buff___6_1_0 {
    u8 vlan_present : 1; // 1 位标志，表示该数据包是否包含 VLAN 标签。
} __attribute__((preserve_access_index));

#endif /* __CORE_PROBE_KERNEL_BPF_COMPAT__ */
