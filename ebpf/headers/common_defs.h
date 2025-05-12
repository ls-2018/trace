#ifndef __CORE_PROBE_COMMON_DEFS__
#define __CORE_PROBE_COMMON_DEFS__

#include <bpf/bpf_helpers.h>
#include <vmlinux.h>

// 在生成绑定时跳过指定的 `type` 不进行处理。
#ifdef __BINDGEN__
#    define BINDING_PTR(type, member) void *member
#else
#    define BINDING_PTR(type, member) type member
#endif

// 不要对结构体成员进行内存对齐，而是按照定义顺序紧凑地排列结构体成员，不插入任何填充字节
#define __packed __attribute__((packed))
// 给 struct 打上特定的标签
#define __binding __attribute__((annotate("uapi")))

// 在 eBPF 和 Rust 之间共享的值处，应使用单一变体的枚举来替代定义。
#define BINDING_DEF(def, val) enum enum_##def{def = (val)} __binding;

/* 与它的 Rust 版本保持同步 crate::core::probe */
#define PROBE_MAX 1024

// 全局探查配置，由内核探查和用户探查共享使用。与它的 Rust 版本保持同步 crate::core::probe::common.
struct retis_global_config {
    u8 enabled;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u8);
    __type(value, struct retis_global_config);
} global_config_map SEC(".maps");

static __always_inline bool collection_enabled() {
    const u8 key = 0;
    const struct retis_global_config *cfg = bpf_map_lookup_elem(&global_config_map, &key);
    return cfg && !!cfg->enabled;
}

#define COMMON_SECTION_CORE 0 // 公共部分核心部分
#define COMMON_SECTION_TASK 1

enum {
    LOG_ERROR = 1,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_TRACE,
};

// 当前的日志级别。实际上是由用户空间设定的。
const volatile u8 log_level = LOG_INFO;

// 日志宏的使用必须谨慎，并且最好是在 {error、slow} 路径中进行。
// 有用的异常情况必须使用较高的日志级别（理想情况下应为 LOG_TRACE）。
#define retis_log(lvl, fmt, args...)                                                                          \
    ({                                                                                                        \
        if (lvl <= log_level) {                                                                               \
            struct retis_log_event *__log = bpf_ringbuf_reserve(&log_map, sizeof(struct retis_log_event), 0); \
            if (__log) {                                                                                      \
                __log->level = lvl;                                                                           \
                BPF_SNPRINTF(__log->msg, sizeof(__log->msg), fmt, args);                                      \
                bpf_ringbuf_submit(__log, BPF_RB_FORCE_WAKEUP);                                               \
            }                                                                                                 \
        }                                                                                                     \
    })

#define log_error(fmt, args...) retis_log(LOG_ERROR, fmt, args)
#define log_warning(fmt, args...) retis_log(LOG_WARN, fmt, args)
#define log_info(fmt, args...) retis_log(LOG_INFO, fmt, args)
#define log_debug(fmt, args...) retis_log(LOG_DEBUG, fmt, args)
#define log_trace(fmt, args...) retis_log(LOG_TRACE, fmt, args)

struct retis_counters_key {
    // 符号地址
    u64 sym_addr;
    // 进程的进程标识符。零值用于内核，因为通常该值被预留给了交换任务。
    u64 pid;
};

// 包含错误路径的计数器信息。随后这些信息会在用户空间中进行处理并予以报告。
struct retis_counters {
    u64 dropped_events;
};

// 探针配置；key是目标符号地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROBE_MAX);
    __type(key, struct retis_counters_key);
    __type(value, struct retis_counters);
} counters_map SEC(".maps");

static __always_inline void err_report(u64 sym_addr, u32 pid) {
    struct retis_counters_key key;

    key.pid = pid;
    key.sym_addr = sym_addr;
    struct retis_counters *err_counters = bpf_map_lookup_elem(&counters_map, &key);
    // 仅在存在数据时进行更新。此处若有任何错误，应通过专用的跟踪管道进行报告。
    if (err_counters)
        __sync_fetch_and_add(&err_counters->dropped_events, 1);
}

#ifndef likely
// y 只是个编译器优化提示，不会影响逻辑
// 返回!!(x)，但我告诉编译器，它通常情况下是 1
// 编译器会据此安排机器指令的布局（比如跳转目标）来提高 CPU 分支预测命中率。
#    define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#    define unlikely(x) __builtin_expect(!!(x), 0)
#endif

// 向上取整
#define DIV_CEIL(m, n) (1 + ((m) - 1) / (n))

#endif /* __CORE_PROBE_COMMON_DEFS__ */
