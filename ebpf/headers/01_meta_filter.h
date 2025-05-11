#ifndef __CORE_FILTERS_META_FILTER__
#define __CORE_FILTERS_META_FILTER__

#include <00_common_defs.h>

#define META_OPS_MAX 32
#define META_TARGET_MAX 32

enum retis_meta_cmp {
    RETIS_EQ = 0,
    RETIS_GT = 1,
    RETIS_LT = 2,
    RETIS_GE = 3,
    RETIS_LE = 4,
    RETIS_NE = 5,
};

enum retis_meta_type {
    RETIS_CHAR = 1,
    RETIS_SHORT,
    RETIS_INT,
    RETIS_LONG,
};

union retis_meta_op
{
    struct {
        u8 type;    // 元数据类型，例如 IP、端口、协议等
        u8 nmemb;   // 成员数量，可能用于数组或结构体中的字段计数
        u16 offt;   // 偏移地址，用于定位字段在结构体或数据包中的位置
        u8 bf_size; // 位字段大小，可能表示多少位有效（位图）
        u64 mask;   // 掩码，用于字段匹配（例如过滤某几个 bit）
    } l;
    struct {
        u8 md[META_TARGET_MAX]; // 目标数据值（即你要比较的值），比如一个 IP 地址或端口号
        u8 sz;                  // 数据大小（字节）
        u8 cmp;                 // 比较操作符，例如 ==、!=、<，由 retis_meta_cmp 枚举定义
    } t __attribute__((aligned(8)));
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, META_OPS_MAX);
    __type(key, u32); // 目标符号地址
    __type(value, union retis_meta_op);
} filter_meta_map SEC(".maps");

struct retis_meta_ctx {
    void *base; // 基准地址，读取数据的起点（比如 skb、struct header等）
    u16 offset; // 相对于 base 的偏移（单位字节）
    u8 type;    // 值的类型，如整型、布尔、结构体中的某字段等
    u8 nmemb;   // 可选：如果是数组，表示成员数量（number of members）
    u8 bfs;     // 可选：bitfield size，若字段是位域，用这个指定其大小（单位：位）

    // 目标值（匹配目标）：
    void *data; // 指向用于比较的目标值，比如要匹配的整数、数组等
    u8 sz;      // 目标值的大小（字节数），如果不为 0 用于验证长度
    u64 mask;   // 比较时使用的掩码（仅对无符号数有效，如 0xff, 0xffff 等）
    u8 cmp;     // 比较操作符，如等于、大于、小于、位与、位或等
};

#define PTR_BIT 1 << 6
#define SIGN_BIT 1 << 7

// 这个全局只读变量用于跟踪 filter_meta_map 中的过滤器数量。当它的值为 0 时，表示没有任何过滤器被应用。
const volatile u32 nmeta = 0;

static __always_inline long meta_process_ops(struct retis_meta_ctx *ctx) {
    u32 k = 0;
    u64 ptr;
    u32 i;

    union retis_meta_op *val = bpf_map_lookup_elem(&filter_meta_map, &k);
    if (!val) {
        log_error("Failed to lookup meta-filter target");
        return -1;
    }

    /* process target */
    ctx->data = &val->t.md;
    ctx->cmp = val->t.cmp;
    ctx->sz = val->t.sz;

    for (i = 1, k = 1; i < nmeta; k++, i++) {
        val = bpf_map_lookup_elem(&filter_meta_map, &k);
        if (!val) {
            log_error("Failed to lookup meta-filter member at index %u", i);
            return -1;
        }

        /* Load Pointer */
        if (val->l.type == PTR_BIT) {
            if (bpf_probe_read_kernel(&ptr, sizeof(void *), (char *)ctx->base + (val->l.offt)))
                return -1;

            // 这可能是为了将地址对齐到 4K 或更大页面边界（如 4MB 页等），或只保留上位地址作为分类标识。
            ctx->base = val->l.mask ? (void *)(ptr & val->l.mask) : (void *)ptr;
            continue;
        }

        /* Non intermediate */
        ctx->offset = val->l.offt;
        ctx->type = val->l.type;
        ctx->mask = val->l.mask;
        ctx->nmemb = val->l.nmemb;
        ctx->bfs = val->l.bf_size;
    }

    return 0;
}

static __always_inline bool cmp_num(u64 operand1, u64 mmask, u64 operand2, bool sign_bit, u8 cmp_type) {
    if (!sign_bit && mmask) // u64 && mmask
        operand1 &= mmask;

    switch (cmp_type) {
        case RETIS_EQ:
            return (operand1 == operand2);
        case RETIS_NE:
            return (operand1 != operand2);
        case RETIS_GT:
            return sign_bit ? ((s64)operand1 > (s64)operand2) : ((u64)operand1 > (u64)operand2);
        case RETIS_LT:
            return sign_bit ? ((s64)operand1 < (s64)operand2) : ((u64)operand1 < (u64)operand2);
        case RETIS_GE:
            return sign_bit ? ((s64)operand1 >= (s64)operand2) : ((u64)operand1 >= (u64)operand2);
        case RETIS_LE:
            return sign_bit ? ((s64)operand1 <= (s64)operand2) : ((u64)operand1 <= (u64)operand2);
        default:
            log_error("Wrong comparison operator %d", cmp_type);
            break;
    }

    return false;
}

static __always_inline bool cmp_bytes(struct retis_meta_ctx *ctx) {
    char val[META_TARGET_MAX] = {0};
    bool ret;
    long sz;

    /* if it is an array of chars use its size. Alternatively, use
     * the target size (probe read could fail in this case).
     * Note: for some reason the one-liner version of this fails to
     * generate code accepted by the verifier. Broken in two lines
     * to workaround that issue.
     */
    sz = ctx->nmemb ?: ctx->sz;
    sz = MIN(sz, sizeof(val));

    if (sz <= 0) {
        log_error("Wrong size (%ld) for bytes comparison", sz);
        return false;
    }

    if (bpf_probe_read_kernel_str(val, sz, (char *)ctx->base + ctx->offset) < 0)
        return 0;

    const char *sp1 = ctx->data, *sp2 = val;

    do {
        ret = *sp1 - *sp2;
        if (ret)
            break;

        if (!(*sp1++ && *sp2++))
            break;
    } while (--sz > 0);

    return !ret;
}

static __always_inline bool filter_bytes(struct retis_meta_ctx *ctx) {
    bool ret = cmp_bytes(ctx);

    switch (ctx->cmp) {
        case RETIS_EQ:
            return ret;
        case RETIS_NE:
            return !ret;
        default:
            log_error("Wrong comparison operator %d", ctx->cmp);
            break;
    }

    return false;
}

// 提取位字段时，需要去掉不相关的前后位，然后考虑右移操作的行为是否会影响符号位。
// Clang 和 GCC 都使用符号扩展，这让我们在提取带符号字段时不会丢失负号。
static __always_inline u64 extract_bf(u64 val, bool has_sign, u16 bit_off, u16 bit_sz) {
    val <<= (64 - bit_sz) - (bit_off % 8);
    return has_sign ? (s64)val >> (64 - bit_sz) : val >> (64 - bit_sz);
}

static __always_inline u64 fixup_signed(u64 val, u32 sz) {
    u64 ret;

    switch (sz) {
        case 4:
            ret = (u64)(s32)val;
            break;
        case 2:
            ret = (u64)(s16)val;
            break;
        case 1:
            ret = (u64)(s8)val;
            break;
        default:
            ret = val;
            break;
    }

    return ret;
}

static __always_inline unsigned int filter_num(struct retis_meta_ctx *ctx) {
    bool sign_bit = ctx->type & SIGN_BIT;
    u64 tval, mval = 0;
    u16 offset;
    u32 sz;

    if (ctx->bfs) { // 有比特
        offset = ctx->offset / 8;
        //    10 - 17
        //  8    16   24
        sz = DIV_CEIL(ctx->bfs + (ctx->offset - offset * 8U), 8);
        if (!sz)
            return 0;
    }
    else {
        sz = ctx->sz;
        offset = ctx->offset;
    }

    sz = MIN(sz, sizeof(mval)); // 尧都区的字节数
    if (!sz) {
        log_error("error while calculating bytes to read (zero not allowed)");
        return 0;
    }
    // 读取一个64 bit 的值； 最多提取 64 位（可以根据需求修改支持 128+）。
    if (bpf_probe_read_kernel(&mval, sz, (char *)ctx->base + offset))
        return 0;

    // 由于位字段可能位于任意 bit 偏移处且被紧凑打包，
    // 它们必须通过专门的逻辑正确提取，不能像普通字段那样直接做比较。

    if (ctx->bfs) {
        mval = extract_bf(mval, sign_bit, ctx->offset, ctx->bfs);
    }
    else if (sign_bit)
        mval = fixup_signed(mval, sz);

    tval = *((u64 *)ctx->data);

    return cmp_num(mval, ctx->mask, tval, sign_bit, ctx->cmp);
}

static __always_inline unsigned int meta_filter(struct sk_buff *skb) {
    struct retis_meta_ctx ctx = {};

    // 将操作简化为加载/比较信息的步骤。如果没有相关条目，则返回匹配结果。
    // <=0  或者 > 32 直接认为匹配成功
    if (!nmeta || nmeta > META_OPS_MAX) // 1 用于记录匹配成功的过滤器标识
        return 1;

    ctx.base = skb;

    if (meta_process_ops(&ctx) < 0 || !ctx.data)
        return 0;

    if (ctx.type & PTR_BIT || ctx.nmemb > 0)
        return filter_bytes(&ctx);

    return filter_num(&ctx);
}

#endif
