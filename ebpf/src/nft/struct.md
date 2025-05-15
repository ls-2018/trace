

```
# 跟踪 Netfilter 表中数据包处理过程的状态信息
struct nft_traceinfo {
    bool trace;                                 // 是否启用该数据包的追踪标志位。如果为 true，则表示正在追踪这个数据包在 nftables 表中的处理过程。。
    bool nf_trace;                              // Netfilter 层级的追踪标志；可能用于与其他 Netfilter 组件交互时确认是否跟踪。
    bool packet_dumped;                         // 表示这个数据包是否已经被记录（例如输出到日志或调试用的追踪 buffer），防止重复记录。
    enum nft_trace_types type : 8;              // 跟踪的类型，是一个枚举类型，可能表示触发跟踪的规则类型或操作，例如规则匹配、动作等。使用 : 8 指定只用 8 位保存该值。
    u32 skbid;                                  // socket buffer 的 ID（skb id），用于唯一标识一个网络数据包。
    const struct nft_base_chain *basechain;     // 指向基础链（如 input、output、forward 等）的指针，表示追踪是在哪条链中触发的。
};

# 动态表示规则数据的结构体
struct nft_rule_dp {
    u64 is_last : 1;         // 表示这是否是规则链中的最后一条规则。1 表示是最后一条，0 表示后面还有规则。
    u64 dlen : 12;           // 当前规则的数据长度（data[] 的长度），单位是字节。
    u64 handle : 42;         // 规则的唯一标识符，用于对规则的引用、删除或查找。42 位足以容纳大量规则。
    long : 0;                // 这是一个 GCC 扩展：将后续成员对齐到 long 类型的边界，确保 data[] 部分地址对齐。
    unsigned char data[0];   // 零长度数组，也叫 flexible array member，实际长度由 dlen 决定，存放具体规则字节数据。
};

struct nft_verdict {
    u32 code;                // 仅当 code 表示的是 NFT_JUMP 或 NFT_GOTO 这类跳转判决时，这个字段才有意义。 
    struct nft_chain *chain; // 指向 nft_chain 结构体的指针，表示目标链（chain）。
};



                             +------------------------+
                             |    输入参数:           |
                             |  - struct nft_traceinfo *info
                             |  - struct nft_rule_dp *rule (可能为 NULL)
                             |  - struct nft_chain *chain (可选传入)
                             +------------------------+
                                         |
                                         ▼
                   +------------------------ 判断路径 ---------------------------+
                   |                                                            |
         +-------------------+                                       +--------------------+
         | rule 为 非NULL     |                                       | rule  NULL     |
         +--------+----------+                                       +---------+----------+
                  |                                                           |
                  |                                                           |
         +--------▼----------+                                     +----------▼-----------+
         | 从 info->basechain->chain 提取链                       | 判断 rule->is_last？  |
         |                                                       +----------+------------+
         +--------+----------+                                   |         |             |
                  |                                              |         |             |
        +---------▼------------+                     +-----------▼--+   +--▼------------------+
        | 设置 chain = info->basechain->chain         | 是最后规则？ |   | 不是最后规则？     |
        +----------------------+                     +-------------+   +----------------------+
                                                        |                          |
                                                        ▼                          ▼
                                            chain = last->chain        chain 来自上层或未知

```