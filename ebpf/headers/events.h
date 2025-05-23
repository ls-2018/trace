#ifndef __CORE_PROBE_KERNEL_BPF_EVENTS__
#define __CORE_PROBE_KERNEL_BPF_EVENTS__

#include <vmlinux.h>

#include <common_defs.h>

// 请确保以下内容与对应的 Rust 版本保持一致。
#define EVENTS_MAX 8 * 1024
#define RAW_EVENT_DATA_SIZE 1024 - 2
#define RETIS_MAX_COMM 64

#define LOG_MAX 127

BINDING_DEF(LOG_EVENTS_MAX, 128)

struct retis_log_event {
    u8 level;
    char msg[LOG_MAX];
} __binding;

// 事件类型
enum retis_event_owners {
    COMMON = 1,
    KERNEL = 2,
    USERSPACE = 3,
    COLLECTOR_SKB_TRACKING = 4,
    COLLECTOR_SKB_DROP = 5,
    COLLECTOR_SKB = 6,
    COLLECTOR_OVS = 7,
    COLLECTOR_NFT = 8,
    COLLECTOR_CT = 9,
};

struct retis_raw_event {
    u16 size;
    u8 data[RAW_EVENT_DATA_SIZE]; //    [0-size,retis_raw_event_section_header,size2,]
} __packed;

struct retis_raw_event_section_header {
    u8 owner;
    u8 data_type;
    u16 size;
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, sizeof(struct retis_raw_event) * EVENTS_MAX); //  * 1024
} events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, sizeof(struct retis_log_event) * LOG_EVENTS_MAX); // 128
} log_map SEC(".maps");

static __always_inline struct retis_raw_event *get_event() {
    struct retis_raw_event *event = bpf_ringbuf_reserve(&events_map, sizeof(*event), 0);
    if (!event) {
        return NULL;
    }

    event->size = 0;
    return event;
}

static __always_inline void discard_event(struct retis_raw_event *event) {
    bpf_ringbuf_discard(event, 0);
}

static __always_inline void send_event(struct retis_raw_event *event) {
    bpf_ringbuf_submit(event, 0);
}

// 添加完 retis_raw_event_section_header 后的偏移地址
static __always_inline void *get_event_section(struct retis_raw_event *event, u8 owner, u8 data_type, u16 size) {
    struct retis_raw_event_section_header *header;

    if (unlikely(event->size > sizeof(event->data))) {
        return NULL;
    }

    const u16 requested = sizeof(*header) + size;
    const u16 left = sizeof(event->data) - event->size;

    if (unlikely(requested > left)) {
        log_error("Failed to get event section: no space left (%u > %u)", requested, left);
        return NULL;
    }

    header = (struct retis_raw_event_section_header *)(event->data + event->size);
    header->owner = owner;
    header->data_type = data_type;
    header->size = size;

    void *section = (void *)header + sizeof(*header);
    event->size += requested;

    return section;
}

static __always_inline void *get_event_zsection(struct retis_raw_event *event, u8 owner, u8 data_type, const u16 size) {
    void *section = get_event_section(event, owner, data_type, size);

    if (!section)
        return NULL;

    __builtin_memset(section, 0, size);
    return section;
}

static __always_inline u16 get_event_size(struct retis_raw_event *event) {
    return event->size;
}

struct common_event {
    u64 timestamp;
    u32 smp_id;
} __binding;

struct common_task_event {
    u64 pid;
    char comm[RETIS_MAX_COMM]; // 64
} __binding;

#endif /* __CORE_PROBE_KERNEL_BPF_EVENTS__ */
