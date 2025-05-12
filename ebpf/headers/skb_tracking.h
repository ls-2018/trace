#ifndef __CORE_FILTERS_SKB_TRACKING__
#define __CORE_FILTERS_SKB_TRACKING__

#include <bpf/bpf_core_read.h>
#include <vmlinux.h>

#include <retis_context.h>

struct tracking_config {
    // 该函数是否在 释放 skb
    // 如果为 1，说明这个函数调用了如 kfree_skb() 这样的释放函数
    u8 free;
    // 函数对 skb 进行了 部分释放。
    // 将当前 skb 的数据合并到另一个 skb 中，但没有释放原来的头部。
    // 比如在 GRO（Generic Receive Offload）处理流程中可能发生
    u8 partial_free;
    // 函数 使 skb 的头部失效
    // 意思是它修改了 skb 的头部指针、长度或元信息，使得追踪头部信息变得不可靠。
    // 例如对 skb 做 skb_pull()、skb_trim() 等操作时，原头部内容被改变
    u8 inv_head;
    // 表示这个函数是一个 特殊函数，不应添加新的追踪信息。
    // 但已经存在的追踪信息可以读取。
    // 这通常用于“只读探针”  我们不往追踪系统中注入新状态，只观察已有状态。
    u8 no_tracking;
} __packed __binding;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROBE_MAX); // 1024
    __type(key, u64);               // 函数地址
    __type(value, struct tracking_config);
} tracking_config_map SEC(".maps");

struct tracking_info {
    u64 timestamp;
    u64 last_seen;
    u64 orig_head;
} __binding;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct tracking_info);
} tracking_map SEC(".maps");

// 必须与有效的 sk_buff 指针一起使用
static __always_inline struct tracking_info *skb_tracking_info(struct sk_buff *skb) {
    struct tracking_info *ti = NULL;
    u64 head;

    head = (u64)BPF_CORE_READ(skb, head);
    if (!head)
        return 0;

    ti = bpf_map_lookup_elem(&tracking_map, &head);
    if (!ti)
        // 它可能会通过其 skb 地址进行临时存储。
        ti = bpf_map_lookup_elem(&tracking_map, (u64 *)&skb);

    return ti;
}

static __always_inline int track_skb_start(struct retis_context *ctx) {
    bool inv_head = false;
    bool no_tracking = false;
    struct tracking_info *ti = NULL, new;
    u64 head, ksym = ctx->ksym;

    struct sk_buff *skb = retis_get_sk_buff(ctx);
    if (!skb)
        return 0;

    // 尝试获取这个符号的追踪配置，
    struct tracking_config *cfg = bpf_map_lookup_elem(&tracking_config_map, &ksym);
    if (cfg) {
        inv_head = cfg->inv_head;
        no_tracking = cfg->no_tracking;
    }

    head = (u64)BPF_CORE_READ(skb, head);
    if (!head)
        return 0;

    ti = bpf_map_lookup_elem(&tracking_map, &head);

    if (!ti) {                                                // 未为此套接字缓冲区（skb）找到跟踪信息。
        ti = bpf_map_lookup_elem(&tracking_map, (u64 *)&skb); // 它可能会暂时使用其 skb 地址来存储它。
        if (ti) {
            // 如果找到了，从现在起就按照其数据地址对其进行索引，就像其他情况一样。
            bpf_map_delete_elem(&tracking_map, (u64 *)&skb);
            bpf_map_update_elem(&tracking_map, &head, ti, BPF_NOEXIST);
        }
    }

    if (!ti) { // 仍然为空，这是我们首次见到这个 skb。创建一个新的跟踪信息。
        if (no_tracking) {
            return 0;
        }

        ti = &new;
        ti->timestamp = ctx->timestamp;
        ti->last_seen = ctx->timestamp;
        ti->orig_head = head;

        // 如果首次遇到这个 sk_buff 的时候它已经被释放了，那么就不需要进行全局追踪了。
        bpf_map_update_elem(&tracking_map, &head, &new, BPF_NOEXIST);
    }

    // 记录我们上次看到这个 skb 的时间，因为如果遗漏了某些事件，清理跟踪映射条目时就会很有用。
    ti->last_seen = ctx->timestamp;

    // 如果该函数破坏了 sk_buff 头部的完整性，我们就无法得知新的头部值会是什么。此时，我们可以暂时通过 sk_buff 的地址来对其进行跟踪。
    if (inv_head)
        bpf_map_update_elem(&tracking_map, (u64 *)&skb, ti, BPF_NOEXIST);

    return 0;
}

static __always_inline int track_skb_end(struct retis_context *ctx) {
    u64 head, ksym = ctx->ksym;

    struct tracking_config *cfg = bpf_map_lookup_elem(&tracking_config_map, &ksym);
    if (!cfg)
        return 0;

    // 我们仅支持下面列出的释放（free）函数。
    if (!cfg->free)
        return 0;

    struct sk_buff *skb = retis_get_sk_buff(ctx);
    if (!skb)
        return 0;

    head = (u64)BPF_CORE_READ(skb, head);
    if (!head)
        return 0;
    // kfree_skb            完整地释放一个 skb 结构体，包括它的数据缓冲区和控制结构体本身。
    // kfree_skb_partial    只释放 skb 的元信息（控制结构），不释放数据缓冲区。

    if (cfg->partial_free) {
        bool stolen = retis_get_param(ctx, 1, bool); // 获取 kfree_skb_partial 函数的第二个参数
        if (!stolen)
            return 0;
    }

    bpf_map_delete_elem(&tracking_map, &head);

    return 0;
}

// 必须与有效的 sk_buff 指针一起使用
static __always_inline bool skb_is_tracked(struct sk_buff *skb) {
    return skb_tracking_info(skb) != NULL;
}

#endif /* __CORE_FILTERS_SKB_TRACKING__ */
