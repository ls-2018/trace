#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <compat.h>

#define VERD_SCALE (NFT_RETURN * -1)
#define ALLOWED_VERDICTS(verd, mask) (1 << (verd + VERD_SCALE) & mask)
#define NFT_NAME_SIZE 128

struct nft_offsets {
    s8 nft_chain;
    s8 nft_rule;
    s8 nft_verdict;
    s8 nft_type;
};

struct nft_config {
    u64 verdicts; // 要追踪 的 nft 匹配结果
    struct nft_offsets offsets;
} __binding;

// nft_config
#define retis_get_nft_chain(ctx, cfg) RETIS_HOOK_GET(ctx, cfg->offsets, nft_chain, struct nft_chain *)
#define retis_get_nft_rule(ctx, cfg) RETIS_HOOK_GET(ctx, cfg->offsets, nft_rule, struct nft_rule_dp *)
#define retis_get_nft_verdict(ctx, cfg) RETIS_HOOK_GET(ctx, cfg->offsets, nft_verdict, struct nft_verdict *)
#define retis_get_nft_type(ctx, cfg) RETIS_HOOK_GET(ctx, cfg->offsets, nft_type, enum nft_trace_types)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct nft_config);
} nft_config_map SEC(".maps");

struct nft_event {
    char table_name[NFT_NAME_SIZE];         // 表名，大小为 128 字节
    char chain_name[NFT_NAME_SIZE];         // 链名，大小为 128 字节
    u32 verdict;                            // 判决（verdict），例如 ACCEPT、DROP 等
    char verdict_chain_name[NFT_NAME_SIZE]; // 如果是跳转（JUMP/GOTO）之类的 verdict，这里是目标链名
    s64 t_handle;                           // 表的 handle（唯一标识符），64 位整数
    s64 c_handle;                           // 链的 handle，64 位整数
    s64 r_handle;                           // 规则的 handle，64 位整数
    u8 policy;                              // 默认策略，例如 NF_ACCEPT、NF_DROP 等
} __binding;

// 如果这个 trace 是一个 NFT_TRACETYPE_RETURN 类型（意味着规则链返回了），
// 且其 verdict.code 是 NFT_CONTINUE（表示未做处理，继续执行下一规则），
// 那么我们不认为有有效 rule handle，返回 -1。
#define __nft_get_rule_handle(__info, __verdict, __rule)                                                                       \
    ({                                                                                                                         \
        if (BPF_CORE_READ_BITFIELD_PROBED(info, type) == NFT_TRACETYPE_RETURN && BPF_CORE_READ(verdict, code) == NFT_CONTINUE) \
            return -1;                                                                                                         \
        (u64) BPF_CORE_READ_BITFIELD_PROBED(__rule, handle);                                                                   \
    })

// is_last 用来判断当前规则是不是“最后一条”规则
static __always_inline s64 nft_get_rule_handle(const struct nft_traceinfo *info, const struct nft_verdict *verdict, const void *rule) {
    if (!rule || !verdict || !info)
        return -1;

    if (bpf_core_type_exists(struct nft_rule_dp___5_17_0)) {
        const struct nft_rule_dp___5_17_0 *r = rule;
        if (BPF_CORE_READ_BITFIELD_PROBED(r, is_last))
            return -1;

        return __nft_get_rule_handle(info, verdict, r);
    }
    else if (bpf_core_type_exists(struct nft_rule___3_13_0)) {
        const struct nft_rule___3_13_0 *r = rule;
        return __nft_get_rule_handle(info, verdict, r);
    }
    else {
        // 这应该触发一个警告，该警告必须由用户空间返回处理。
        return -1;
    }
}

static __always_inline int nft_trace(struct nft_config *cfg, struct retis_raw_event *event, const struct nft_traceinfo *info, const struct nft_chain *chain, const struct nft_verdict *verdict, const void *rule, enum nft_trace_types type) {
    // NFT_TRACETYPE_UNSPEC = 0,    表示没有指定的跟踪类型，通常是默认值或无效值。
    // NFT_TRACETYPE_POLICY = 1,    用于指示包在链的末尾时被默认策略（如 ACCEPT 或 DROP）处理。这是“链策略”的跟踪事件。
    // NFT_TRACETYPE_RETURN = 2,    表示在执行 return 指令时的跟踪事件。通常用于从子链返回主链时。
    // NFT_TRACETYPE_RULE = 3,      规则命中跟踪（Rule trace）

    // nft_verdict.code
    // 低 8 位（低字节）：表示实际的 verdict 类型，比如 NF_ACCEPT（接受）、NF_DROP（丢弃）、NFT_GOTO、NFT_JUMP 等。
    // 高位部分：如果是 GOTO 或 JUMP 类型，剩下的高位用于指定跳转到的链（chain）的编号。

    const u8 policy = (type == NFT_TRACETYPE_POLICY);
    const u32 code = policy ? (u32)BPF_CORE_READ(info, basechain, policy) : (u32)BPF_CORE_READ(verdict, code);
    if (!ALLOWED_VERDICTS(code, cfg->verdicts))
        return -ENOMSG;

    struct nft_event *e = get_event_zsection(event, COLLECTOR_NFT, 1, sizeof(*e));
    if (!e)
        return 0;

    e->policy = policy;
    e->verdict = code;

    /* Table info */
    const char *name = BPF_CORE_READ(chain, table, name); // 跳转的表名
    bpf_probe_read_kernel_str(e->table_name, sizeof(e->table_name), name);

    /* Chain info */
    name = BPF_CORE_READ(chain, name);
    bpf_probe_read_kernel_str(e->chain_name, sizeof(e->chain_name), name);

    name = BPF_CORE_READ(verdict, chain, name);
    bpf_probe_read_kernel_str(e->verdict_chain_name, sizeof(e->verdict_chain_name), name);
    e->t_handle = BPF_CORE_READ(chain, table, handle);
    e->c_handle = BPF_CORE_READ(chain, handle);
    e->r_handle = nft_get_rule_handle(info, verdict, rule);

    return 0;
}

static __always_inline const struct nft_chain *nft_get_chain_from_rule(struct retis_context *ctx, struct nft_traceinfo *info, const struct nft_rule_dp *rule) {
    const struct nft_rule_dp_last___6_4_0 *last = NULL;

    if (!rule) {
        const struct nft_base_chain *base_chain = BPF_CORE_READ(info, basechain);
        if (!base_chain)
            return NULL;

        return (void *)base_chain + bpf_core_field_offset(base_chain->chain);
    }

    /* FIXME: This should ideally be bpf_core_type_exists(struct
     * nft_rule_dp_last___6_4_0). For the time being this could not be
     * done because of compilers and the way programs are built.
     */
    struct nft_traceinfo___6_3_0 *info_63 = (struct nft_traceinfo___6_3_0 *)info;
    if (!bpf_core_field_exists(info_63->rule)) {
        // 最多尝试1024 次
        for (int i = 0; i < 1024; i++) {
            if (BPF_CORE_READ_BITFIELD_PROBED(rule, is_last)) {
                last = (void *)rule;
                break;
            }

            const u64 rule_dlen = BPF_CORE_READ_BITFIELD_PROBED(rule, dlen);
            rule = (void *)rule + sizeof(*rule) + rule_dlen;
        }

        return BPF_CORE_READ(last, chain);
    }

    return NULL;
}

/* Depending on the kernel:
 * 在某些内核版本中：rule 是通过 info 来间接获取的；chain 是作为参数直接传入的。
 * - rule is under info, chain is a parameter
 *   - rule type is nft_rule
 *   - rule type is nft_rule_dp
 * 在另一些场景下：rule 本身是直接传入的参数；chain 的获取依据条件而定：
 * - rule is a parameter, chain is one of:
 *   - last->chain; if rule->is_last
 *   - info->basechain->chain; if !rule
 *
 * The function deal with that and other than the rule, it also
 * retrieves the nft_chain pointer.
 */
static __always_inline void nft_retrieve_rule(struct retis_context *ctx, struct nft_config *cfg, struct nft_traceinfo *info, const void **rule, const struct nft_chain **chain) {
    struct nft_traceinfo___6_3_0 *info_63 = (struct nft_traceinfo___6_3_0 *)info;
    if (bpf_core_field_exists(info_63->rule)) {
        *chain = retis_get_nft_chain(ctx, cfg);
        *rule = BPF_CORE_READ(info_63, rule);
        return;
    }

    *rule = retis_get_nft_rule(ctx, cfg);
    *chain = nft_get_chain_from_rule(ctx, info, *rule);
}

static __always_inline const struct nft_verdict *nft_get_verdict(struct retis_context *ctx, struct nft_config *cfg, struct nft_traceinfo *info) {
    const struct nft_verdict *verdict;

    struct nft_traceinfo___6_3_0 *info_63 = (struct nft_traceinfo___6_3_0 *)info;
    if (!bpf_core_field_exists(info_63->verdict))
        verdict = retis_get_nft_verdict(ctx, cfg);
    else
        verdict = BPF_CORE_READ(info_63, verdict);

    return verdict;
}

DEFINE_HOOK(
    F_AND, RETIS_ALL_FILTERS, const struct nft_verdict *verdict; const struct nft_chain *chain; struct nft_traceinfo * info; struct nft_config * cfg; const void *rule; u32 zero = 0;

    cfg = bpf_map_lookup_elem(&nft_config_map, &zero); if (!cfg) return 0;

    /* nft_traceinfo pointer must be present. */
    info = retis_get_nft_traceinfo(ctx);
    if (!info) return 0;

    /* rule can be NULL. */
    nft_retrieve_rule(ctx, cfg, info, &rule, &chain); if (!chain) return 0;

    verdict = nft_get_verdict(ctx, cfg, info);

    return nft_trace(cfg, event, info, chain, verdict, rule, retis_get_nft_type(ctx, cfg));)

char __license[] SEC("license") = "GPL";
