#ifndef __CORE_PROBE_KERNEL_BPF_COMMON__
#define __CORE_PROBE_KERNEL_BPF_COMMON__

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <vmlinux.h>

#include <common_defs.h>
#include <events.h>
#include <helpers.h>
#include <meta_filter.h>
#include <packet_filter.h>
#include <retis_context.h>
#include <skb_tracking.h>

struct kernel_event {
    u64 symbol;    // 存储被探测的内核符号地址
    long stack_id; // 表示当前事件的调用栈 ID
    u8 type;       // 事件的来源类型
} __binding;

struct retis_probe_config {
    struct retis_probe_offsets offsets; // 包含内核中相关结构体字段的偏移信息
    u8 stack_trace;                     // 是否启用调用栈采集
} __binding;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROBE_MAX); // 1024
    __type(key, u64);
    __type(value, struct retis_probe_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 127 * sizeof(u64));
} stack_map SEC(".maps");

#define RETIS_F_PASS(f, v) RETIS_F_##f##_PASS_SH = v, RETIS_F_##f##_PASS = 1 << v

/* Defines the bit position for each filter */
enum {
    RETIS_F_PASS(PACKET, 0),
    RETIS_F_PASS(META, 1),
};

/* Filters chain is an and */
#define F_AND 0
/* Filters chain is an or */
#define F_OR 1

#define RETIS_ALL_FILTERS (RETIS_F_PACKET_PASS | RETIS_F_META_PASS)

#define RETIS_TRACKABLE(mask) (!(mask ^ RETIS_ALL_FILTERS))

/* Helper to define a hook (mostly in collectors) while not having to duplicate
 * the common part everywhere. This also ensure hooks are doing the right thing
 * and should help with maintenance.
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_HOOK(AND_OR_SEL, FILTER_FLAG1 | FILTER_FLAG2 | ...,
 *	do_something(ctx);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_HOOK(fmode, fflags, statements)                                                                \
    SEC("ext/hook")                                                                                           \
    int hook(struct retis_context *ctx, struct retis_raw_event *event) {                                      \
        /* Let the verifier be happy */                                                                       \
        if (!ctx || !event)                                                                                   \
            return 0;                                                                                         \
        if (!((fmode == F_OR) ? (ctx->filters_ret & (fflags)) : ((ctx->filters_ret & (fflags)) == (fflags)))) \
            return 0;                                                                                         \
        statements                                                                                            \
    }

/* Helper that defines a hook that doesn't depend on any filtering
 * result and runs regardless.  Filtering outcome is still available
 * through ctx->filters_ret for actions that need special handling not
 * covered by DEFINE_HOOK([F_AND|F_OR], flags, ...).
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_HOOK_RAW(
 *	do_something(ctx);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_HOOK_RAW(statements) DEFINE_HOOK(F_AND, 0, statements)

// 安装的钩子数量，用于对调用链进行微优化;volatile 避免优化
const volatile u32 nhooks = 0;

// 钩子定义，旨在在程序连接之前被替换掉。
// 这个临时返回值是易变的，目的是不让编译器认为它可以对其进行优化。
// 这要归功于 XDP 中心处理程序。
#define HOOK(x)                                                                                       \
    __attribute__((noinline)) int hook##x(struct retis_context *ctx, struct retis_raw_event *event) { \
        volatile int ret = 0;                                                                         \
        if (!ctx || !event)                                                                           \
            return 0;                                                                                 \
        return ret;                                                                                   \
    }
HOOK(0)
HOOK(1)
HOOK(2)
HOOK(3)
HOOK(4)
HOOK(5)
HOOK(6)
HOOK(7)
HOOK(8)
HOOK(9)
/* Keep in sync with its Rust counterpart in crate::core::probe::kernel */
#define HOOK_MAX 10

__attribute__((noinline)) int ctx_hook(struct retis_context *ctx) {
    // 用途	说明
    // 类型锚点/上下文保留	        ctx 参数被引用一次，能让 verifier 识别其类型。
    // 避免优化丢失	            volatile 和 noinline 用于保持函数形状、避免变量优化。
    // BPF verifier 辅助路径	    某些 verifier 检查依赖于函数存在性和参数类型，这里是辅助构建“合法路径”。

    // return 0  ; 可能会报错    R1 type=ctx expected=ctx, but got unknown or scalar
    volatile int ret = 0;
    if (!ctx)
        return 0;
    return ret;
}

#define DEFINE_CTX_HOOK(statements)       \
    SEC("ext/hook")                       \
    int hook(struct retis_context *ctx) { \
        if (!ctx)                         \
            return 0;                     \
        statements                        \
    }

// 加载时动态替换 BPF 指令
// 调用一个 BPF 子程序并获取其返回值，而且强制使用 BPF 指令语义和寄存器规范
#define FILTER(x)                                                                                                                                                       \
    static __noinline unsigned int filter_##x(void *ctx) {                                                                                                              \
        register void *ctx_reg asm("r1") = ctx; /* 保证 r1 寄存器不会变化 */                                                                                            \
        volatile unsigned int ret;              /* */                                                                                                                   \
        asm volatile("call " s(x) ";"             /* 调用 ebpf 子程序（宏 x 指代子程序名） */                                                           \
			"*(u32 *)%[ret] = r0"                 /* 把 r0 的值写到 ret 上 */                                                                       \
		     : [ret] "=m"(ret)                    /* 输出：ret 是一个内存变量（写）*/                                                               \
		     : "r"(ctx_reg)                       /* 输入：r1 = ctx_reg（刚才绑定好的） */                                                           \
		     : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "memory");  /* clobbers：说明这些寄存器会被用到/修改 */ \
        return ret;                                                                                                                                                     \
    }

FILTER(l2)
FILTER(l3)

static __always_inline void filter(struct retis_context *ctx) {
    struct retis_packet_filter_ctx fctx = {};

    struct sk_buff *skb = retis_get_sk_buff(ctx);
    if (!skb)
        return;
    /* 如果 skb 已经被跟踪，则对数据包过滤逻辑进行特殊处理。这样做在多个方面都有助益，包括：
     * - 提升性能。
     * - 确保能够跟踪数据包的转换过程。
     * - 在数据完全不可用时进行数据包过滤。*/
    if (skb_is_tracked(skb)) {
        ctx->filters_ret |= RETIS_ALL_FILTERS;
        return;
    }

    char *head = (char *)BPF_CORE_READ(skb, head);
    fctx.len = BPF_CORE_READ(skb, len);

    /*
     * L3 过滤器所需的负载更少（这意味着由于内存访问而产生的开销也更小），
     * 并且在 mac_header 不存在（即在传输路径的早期阶段）的情况下也能实现匹配。
     * 尽管存在这种特殊性，但当前的方法较为保守，
     * 在 mac_header 存在时会优先选择 L2 过滤器而非 L3 过滤器。
     */
    if (is_mac_data_valid(skb)) {
        fctx.data = head + BPF_CORE_READ(skb, mac_header);
        ctx->filters_ret |= !!filter_l2(&fctx) << RETIS_F_PACKET_PASS_SH; // 0
        goto next_filter;
    }

    if (!is_network_data_valid(skb))
        return;

    fctx.data = head + BPF_CORE_READ(skb, network_header); // 它是一个 偏移值，表示网络层（如 IP）的头部相对于 skb->head 的地址。

    // L3 过滤器可以设置为“无操作”状态，这意味着仅从 L3 角度来看，这些条件不足以确定匹配关系。
    ctx->filters_ret |= !!filter_l3(&fctx) << RETIS_F_PACKET_PASS_SH; // 0

next_filter:
    ctx->filters_ret |= (!!meta_filter(skb)) << RETIS_F_META_PASS_SH; // 1
}

static __always_inline int extend_ctx_nft(struct retis_context *ctx) {
    // 从偏移量、填充到regs
    const struct nft_pktinfo *pkt;

    if (retis_arg_valid(ctx, sk_buff) || !bpf_core_type_exists(struct nft_traceinfo) || !bpf_core_type_exists(struct nft_pktinfo))
        return 0;

    struct nft_traceinfo *info = retis_get_nft_traceinfo(ctx); // ctx.offset.
    if (!info)
        return 0;

    struct nft_traceinfo___6_3_0 *info_63 = (struct nft_traceinfo___6_3_0 *)info;
    if (bpf_core_field_exists(info_63->pkt))
        pkt = BPF_CORE_READ(info_63, pkt);
    else
        pkt = retis_get_nft_pktinfo(ctx);

    if (pkt)
        retis_set_ext_sk_buff(ctx, BPF_CORE_READ(pkt, skb));

    return 0;
}

static __always_inline int extend_ctx(struct retis_context *ctx) {
    void *orig_ctx;
    int ret;

    ret = extend_ctx_nft(ctx); // ✅
    if (ret)
        return ret;

    /* Builtin context extensions. */
    /* 验证器在识别原始上下文类型时好像会出问题，而这样做能有所帮助。
     */
    orig_ctx = ctx->orig_ctx;
    barrier_var(orig_ctx);
    ret = ctx_hook(ctx);
    ctx->orig_ctx = orig_ctx;

    return ret;
}

/*
 * 链式函数包含了我们所有的核心探测逻辑。它在每个特定探测部分填充完通用上下文并，在返回之前被调用。
 */
static __always_inline int chain(struct retis_context *ctx) {
    struct retis_probe_config *cfg;
    struct retis_raw_event *event;
    // 这里需要使用 volatile，以防止在钩子链前后读取事件使用长度时被优化。

    static bool enabled = false;

    int ret;

    // 检查是否启用了收集功能，否则就退出。一旦确认启用，就将结果缓存起来。
    if (unlikely(!enabled)) {
        enabled = collection_enabled();
        if (!enabled) {
            return 0;
        }
    }

    cfg = bpf_map_lookup_elem(&config_map, &ctx->ksym); // 检查有没有注册对应hook
    if (!cfg) {
        return 0;
    }
    ctx->offsets = cfg->offsets;

    ret = extend_ctx(ctx); // ✅
    if (ret) {
        log_warning("ctx extension failed: %d", ret);
    }

    filter(ctx); // 会填充一些属性
    // 跟踪 skb。注意，这一步是在过滤之后进行的！如果没有可用的 skb，这将不会执行任何操作（no-op）。

    // 重要提示：我们必须尽早执行这一操作，这样即使后续操作失败，跟踪逻辑仍然能够运行；我们不希望因为非致命错误而丢失信息！
    if (RETIS_TRACKABLE(ctx->filters_ret)) {
        track_skb_start(ctx);
    }

    if (nhooks == 0) {
        goto exit;
    }

    event = get_event();
    if (!event) {
        err_report(ctx->ksym, 0);
        goto exit;
    }

    struct common_event *e = get_event_section(event, COMMON, COMMON_SECTION_CORE, sizeof(*e));
    if (!e) {
        goto discard_event;
    }
    // todo ,剩余部分，会不会不足以承载 common_event
    e->timestamp = ctx->timestamp;
    e->smp_id = bpf_get_smp_processor_id();

    struct common_task_event *ti = get_event_zsection(event, COMMON, COMMON_SECTION_TASK, sizeof(*ti));
    if (!ti) {
        goto discard_event;
    }

    ti->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(ti->comm, sizeof(ti->comm));

    struct kernel_event *k = get_event_section(event, KERNEL, 0, sizeof(*k));
    if (!k)
        goto discard_event;

    k->symbol = ctx->ksym;
    k->type = ctx->probe_type;
    if (cfg->stack_trace)
        k->stack_id = bpf_get_stackid(ctx->orig_ctx, &stack_map, BPF_F_FAST_STACK_CMP);
    else
        k->stack_id = -1;

    volatile u16 pass_threshold = get_event_size(event);
    barrier_var(pass_threshold);

// 定义了逐个调用钩子的逻辑。
// 作为临时变通方案，我们会处理 -ENOMSG 错误，并在这种情况下丢弃事件。
// 但这种做法不应被过度使用，应该寻找一个长期的、合理的解决方案。
// 使用这个机制的场景是允许钩子进行某种程度的过滤，否则在某些情况下我们可能会被大量事件淹没，因为如果没有这个机制，钩子只能自行做过滤。
#define ENOMSG 42
#define CALL_HOOK(x)                   \
    if (x < nhooks) {                  \
        int ret = hook##x(ctx, event); \
        if (ret == -ENOMSG)            \
            goto discard_event;        \
    }

    CALL_HOOK(0)
    CALL_HOOK(1)
    CALL_HOOK(2)
    CALL_HOOK(3)
    CALL_HOOK(4)
    CALL_HOOK(5)
    CALL_HOOK(6)
    CALL_HOOK(7)
    CALL_HOOK(8)
    CALL_HOOK(9)

    if (get_event_size(event) > pass_threshold) // todo ,why >
        send_event(event);
    else
    discard_event:
        discard_event(event);

exit:

    if (RETIS_TRACKABLE(ctx->filters_ret))
        track_skb_end(ctx);

    return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
