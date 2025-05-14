#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <vmlinux.h>

#include <common.h>
#include <if_vlan.h>

#define BIT(x) (1 << (x))

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86dd

enum skb_sections {
    SECTION_PACKET = 1,
    SECTION_VLAN,
    SECTION_DEV,
    SECTION_NS,
    SECTION_META,
    SECTION_DATA_REF,
    SECTION_GSO,
} __binding;

/* Skb hook configuration. A map is used to set the config from
 * userspace.
 */
struct skb_config {
    u64 sections;
} __binding;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct skb_config);
} skb_config_map SEC(".maps");

BINDING_DEF(IFNAMSIZ, 16)

struct skb_netdev_event {
    u8 dev_name[IFNAMSIZ]; // 表示网络设备的名字 例如 "eth0"、"lo"。
    u32 ifindex;           // 网络设备的索引号
    u32 iif;               // 输入接口索引（Input Interface Index），也就是数据包是从哪个接口进入的。
} __binding;

struct skb_netns_event {
    u32 netns;
} __binding;

struct skb_meta_event {
    u32 len;       // 报文的总长度（skb->len），包括协议头和数据
    u32 data_len;  // 分片数据的长度，表示有多少数据不在主线性缓冲区（对应 skb->data_len）
    u32 hash;      // skb 哈希值（skb->hash），可能用于流分类
    u8 ip_summed;  // 校验和状态（CHECKSUM_NONE, CHECKSUM_PARTIAL, CHECKSUM_COMPLETE 等）
    u32 csum;      // 报文的校验和值（如果适用）
    u8 csum_level; // 校验级别（如是否嵌套隧道，通常与 ip_summed 联合使用）
    u32 priority;  // skb 优先级（skb->priority），通常用于流控或队列调度
} __binding;

struct skb_data_ref_event {
    u8 nohdr;   // 是否缺少头部数据（可能是 skb->nohdr，表示头部数据未分配或被跳过）
    u8 cloned;  // 表示 skb 是否被克隆（skb->cloned），即多个 skb 实例共享相同的数据缓冲区
    u8 fclone;  // 是否是 "fast clone" skb（skb->fclone），一种特殊的克隆机制，用于优化性能（如 TCP fast clone）
    u8 users;   // skb 实例的引用计数（skb->users），即有多少实体正在引用这个 skb
    u8 dataref; // 数据缓冲区的引用计数（skb_shinfo(skb)->dataref），用于判断数据是否被多个 skb 实例共享
} __binding;

struct skb_gso_event {
    u8 flags;     // GSO 相关标志位（通常是 skb_shinfo(skb)->gso_type 附带的标志，比如是否支持 ECN、TSO 等）
    u8 nr_frags;  // 表示该 skb 使用了多少个 page fragment（skb_shinfo(skb)->nr_frags）
    u32 gso_size; // 每个分段的大小（skb_shinfo(skb)->gso_size），例如每个 TCP 分段大小
    u32 gso_segs; // 总共会被分成多少个分段（skb_shinfo(skb)->gso_segs）
    u32 gso_type; // GSO 类型（如 TCPv4, TCPv6, UDP 等，见 linux/net.h 中 SKB_GSO_* 宏定义）
} __binding;

#define PACKET_CAPTURE_SIZE 255
struct skb_packet_event {
    u32 len;                        // 数据包的实际总长度（skb->len），可能远大于捕获长度
    u32 capture_len;                // 实际被捕获的长度，即 packet[] 中有效字节数，最大不超过 255
    u8 packet[PACKET_CAPTURE_SIZE]; // 捕获的数据包头部内容（通常是前 N 个字节），用于用户空间分析或日志记录
    u8 fake_eth;                    // 标记是否是伪造的以太网头（如在某些虚拟接口或非 L2 skb 中人工补充的 Ethernet header）
} __binding;

// 获取一个 sk_buff 的线性长度
static __always_inline int skb_linear_len(struct sk_buff *skb) {
    return BPF_CORE_READ(skb, len) - BPF_CORE_READ(skb, data_len); // 是当前片（unpaged data）长度
}

// 获取一个 sk_buff 对象的 L3 协议，可以通过查找 sk_buff 的 protocol 字段，或者通过解析数据包的头部来实现。
static __always_inline u16 skb_protocol(struct sk_buff *skb) {
    u16 protocol = BPF_CORE_READ(skb, protocol);
    u8 ip_version;

    if (likely(protocol)) { // 如果设置了，直接返回
        return protocol;
    }

    // 我们 *很有可能* 处于 Tx 路径中；skb->protocol 还未被设置。让我们尝试从数据包内容中检测出协议类型。
    unsigned char *head = BPF_CORE_READ(skb, head);

    // L4 必须先进行设置，因为我们要据此计算 L3 头部的长度。
    if (!is_network_data_valid(skb)      // 3
        || !is_transport_data_valid(skb) // 4
    ) {
        return 0;
    }

    int network = BPF_CORE_READ(skb, network_header);     // 3 偏移值,不是指针  ip   起始地址的偏移量
    int transport = BPF_CORE_READ(skb, transport_header); // 4 偏移值,不是指针   udp\tcp
    int l4hlen = transport - network;                     // ip

    /* Check if the L3 header looks like an IP one. The below is not 100%
     * right (no ext support), but let's stay on the safe side for now.
     */
    // https://en.wikipedia.org/wiki/IPv4#Header
    bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network);
    ip_version >>= 4;
    if (ip_version == 4 && l4hlen == sizeof(struct iphdr)) {
        return bpf_htons(ETH_P_IP);
    }
    else if (ip_version == 6 && l4hlen == sizeof(struct ipv6hdr)) {
        return bpf_htons(ETH_P_IPV6);
    }

    return 0;
}

static __always_inline int process_packet(struct retis_raw_event *event, struct sk_buff *skb) {
    // 请使用整型（int）而非底层（较小的）无符号类型，以便能够进行有符号的算术运算。
    struct skb_packet_event *e;

    const unsigned char *head = BPF_CORE_READ(skb, head);
    const int headroom = BPF_CORE_READ(skb, data) - head;

    const int mac = BPF_CORE_READ(skb, mac_header);
    const u16 network = BPF_CORE_READ(skb, network_header);
    const int linear_len = skb_linear_len(skb);
    u32 len = BPF_CORE_READ(skb, len); // 数据包的实际总长度

    // 线性长度中没有数据，无可报告的内容。
    if (!linear_len)
        return 0;

    if (is_mac_data_valid(skb)) { // 最佳情况：mac偏移量已设置且有效
        long mac_offset = mac - headroom;
        long size = MIN(linear_len - mac_offset, PACKET_CAPTURE_SIZE);
        if (size <= 0)
            return 0;

        e = get_event_section(event, COLLECTOR_SKB, SECTION_PACKET, sizeof(*e));
        if (!e)
            return 0;

        e->len = len - mac_offset;
        e->capture_len = size;
        e->fake_eth = 0;
        bpf_probe_read_kernel(e->packet, size, head + mac);
        /* Valid network offset with an unset or invalid mac offset: we can fake
         * the eth header.
         */
    }
    else if (is_network_data_valid(skb)) {
        u16 etype = skb_protocol(skb);

        /* We do need the ethertype to be set at the skb level here,
         * otherwise we can't guess what kind of packet this is.
         */
        if (!etype)
            return 0;

        long network_offset = network - headroom;
        long size = MIN(linear_len - network_offset, PACKET_CAPTURE_SIZE - sizeof(struct ethhdr));
        if (size <= 0)
            return 0;

        e = get_event_section(event, COLLECTOR_SKB, SECTION_PACKET, sizeof(*e));
        if (!e)
            return 0;

        /* Fake eth header */
        struct ethhdr *eth = (struct ethhdr *)e->packet;
        __builtin_memset(eth, 0, sizeof(*eth));
        eth->h_proto = etype;

        e->len = len - network_offset + sizeof(*eth);
        e->capture_len = size + sizeof(struct ethhdr);
        e->fake_eth = 1;
        bpf_probe_read_kernel(e->packet + sizeof(*eth), size, head + network);
        /* Can't guess any useful packet offset */
    }
    else {
        return 0;
    }

    return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline int process_skb(struct retis_raw_event *event, struct sk_buff *skb) {
    struct skb_shared_info *si;
    struct skb_config *cfg;
    struct net_device *dev;
    u32 key = 0;

    cfg = bpf_map_lookup_elem(&skb_config_map, &key);
    if (!cfg)
        return 0;

    dev = BPF_CORE_READ(skb, dev);

    /* Always retrieve the raw packet */
    process_packet(event, skb);

    if (cfg->sections & BIT(SECTION_DEV) && dev) {
        int ifindex = BPF_CORE_READ(dev, ifindex);

        if (ifindex > 0) {
            struct skb_netdev_event *e = get_event_section(event, COLLECTOR_SKB, SECTION_DEV, sizeof(*e));
            if (!e)
                return 0;

            bpf_probe_read(e->dev_name, IFNAMSIZ, dev->name);
            e->ifindex = ifindex;
            e->iif = BPF_CORE_READ(skb, skb_iif);
        }
    }

    if (cfg->sections & BIT(SECTION_NS)) {
        struct skb_netns_event *e;
        u32 netns;

        /* If the network device is initialized in the skb, use it to
         * get the network namespace; otherwise try getting the network
         * namespace from the skb associated socket.
         */
        if (dev) {
            netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
        }
        else {
            struct sock *sk = BPF_CORE_READ(skb, sk);

            if (!sk)
                goto skip_netns;

            netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
        }

        e = get_event_section(event, COLLECTOR_SKB, SECTION_NS, sizeof(*e));
        if (!e)
            return 0;

        e->netns = netns;
    }

skip_netns:
    if (cfg->sections & BIT(SECTION_META)) {
        struct skb_meta_event *e = get_event_section(event, COLLECTOR_SKB, SECTION_META, sizeof(*e));
        if (!e)
            return 0;

        e->len = BPF_CORE_READ(skb, len);
        e->data_len = BPF_CORE_READ(skb, data_len);
        e->hash = BPF_CORE_READ(skb, hash);
        e->ip_summed = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, ip_summed);
        e->csum = BPF_CORE_READ(skb, csum);
        e->csum_level = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, csum_level);
        e->priority = BPF_CORE_READ(skb, priority);
    }

    if (cfg->sections & BIT(SECTION_DATA_REF)) {
        unsigned char *head = BPF_CORE_READ(skb, head);
        struct skb_data_ref_event *e = get_event_section(event, COLLECTOR_SKB, SECTION_DATA_REF, sizeof(*e));
        if (!e)
            return 0;

        e->nohdr = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, nohdr);
        e->cloned = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);
        e->fclone = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, fclone);
        e->users = (u8)BPF_CORE_READ(skb, users.refs.counter);

        si = (struct skb_shared_info *)(BPF_CORE_READ(skb, end) + head);
        e->dataref = (u8)BPF_CORE_READ(si, dataref.counter);
    }

    if (cfg->sections & BIT(SECTION_VLAN)) {
        bool is_vlan = false;
        bool is_accel = false;
        u16 vlan_tci;

        if (!__vlan_hwaccel_get_tag(skb, &vlan_tci)) {
            is_vlan = true;
            is_accel = true;
        }
        else if (!__vlan_get_tag(skb, &vlan_tci)) {
            is_vlan = true;
        }

        if (is_vlan) {
            struct skb_vlan_event *e = get_event_section(event, COLLECTOR_SKB, SECTION_VLAN, sizeof(*e));
            if (!e)
                return 0;

            set_skb_vlan_event(e, vlan_tci, is_accel);
        }
    }

    if (cfg->sections & BIT(SECTION_GSO)) {
        struct skb_shared_info *shinfo;
        struct skb_gso_event *e;

        /* See skb_shinfo */
        shinfo = (void *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
        /* See skb_is_gso */
        if (!BPF_CORE_READ(shinfo, gso_size))
            goto skip_gso;

        e = get_event_section(event, COLLECTOR_SKB, SECTION_GSO, sizeof(*e));
        if (!e)
            return 0;

        e->flags = bpf_core_field_exists(shinfo->flags) ? BPF_CORE_READ(shinfo, flags) : 0;
        e->nr_frags = BPF_CORE_READ(shinfo, nr_frags);
        e->gso_size = BPF_CORE_READ(shinfo, gso_size);
        e->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
        e->gso_type = BPF_CORE_READ(shinfo, gso_type);
    }

skip_gso:
    return 0;
}

DEFINE_HOOK(
    F_AND, RETIS_ALL_FILTERS, struct sk_buff *skb;

    skb = retis_get_sk_buff(ctx); if (skb) process_skb(event, skb);

    return 0;)

char __license[] SEC("license") = "GPL";
