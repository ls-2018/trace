#ifndef __MODULE_OVS_JHASH_
#define __MODULE_OVS_JHASH_

/* Jenkins的哈希实现主要取自 Linux 内核代码库。
 * (include/linux/jhash.h).
 */

#if __has_attribute(__fallthrough__)
#    define fallthrough __attribute__((__fallthrough__))
#else
#    define fallthrough \
        do {            \
        } while (0) /* fallthrough */
#endif

/*
 * From include/linux/bitopts.h
 */

/*
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift) { // 循环左移shift 位
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/*
 * From include/linux/unaligned/packed_struct.h
 */

static inline u32 __get_unaligned_cpu32(const void *p) {
    const struct __una_u32 *ptr = (const struct __una_u32 *)p;
    return ptr->x;
}

/* Best hash sizes are of power of two */
#define jhash_size(n) ((u32)1 << (n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n) (jhash_size(n) - 1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c) \
    {                        \
        a -= c;              \
        a ^= rol32(c, 4);    \
        c += b;              \
        b -= a;              \
        b ^= rol32(a, 6);    \
        a += c;              \
        c -= b;              \
        c ^= rol32(b, 8);    \
        b += a;              \
        a -= c;              \
        a ^= rol32(c, 16);   \
        c += b;              \
        b -= a;              \
        b ^= rol32(a, 19);   \
        a += c;              \
        c -= b;              \
        c ^= rol32(b, 4);    \
        b += a;              \
    }

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c) \
    {                          \
        c ^= b;                \
        c -= rol32(b, 14);     \
        a ^= c;                \
        a -= rol32(c, 11);     \
        b ^= a;                \
        b -= rol32(a, 25);     \
        c ^= b;                \
        c -= rol32(b, 16);     \
        a ^= c;                \
        a -= rol32(c, 4);      \
        b ^= a;                \
        b -= rol32(a, 14);     \
        c ^= b;                \
        c -= rol32(b, 24);     \
    }

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval) {
    u32 a, b, c;
    const u8 *k = key;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + length + initval;

    /* All but the last block: affect some 32 bits of (a,b,c) */
    while (length > 12) {
        a += __get_unaligned_cpu32(k);
        b += __get_unaligned_cpu32(k + 4);
        c += __get_unaligned_cpu32(k + 8);
        __jhash_mix(a, b, c);
        length -= 12;
        k += 12;
    }
    /* Last block: affect all 32 bits of (c) */
    switch (length) {
        case 12:
            c += (u32)k[11] << 24;
            fallthrough;
        case 11:
            c += (u32)k[10] << 16;
            fallthrough;
        case 10:
            c += (u32)k[9] << 8;
            fallthrough;
        case 9:
            c += k[8];
            fallthrough;
        case 8:
            b += (u32)k[7] << 24;
            fallthrough;
        case 7:
            b += (u32)k[6] << 16;
            fallthrough;
        case 6:
            b += (u32)k[5] << 8;
            fallthrough;
        case 5:
            b += k[4];
            fallthrough;
        case 4:
            a += (u32)k[3] << 24;
            fallthrough;
        case 3:
            a += (u32)k[2] << 16;
            fallthrough;
        case 2:
            a += (u32)k[1] << 8;
            fallthrough;
        case 1:
            a += k[0];
            __jhash_final(a, b, c);
            break;
        case 0: /* Nothing left to add */
            break;
    }

    return c;
}

/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval) {
    u32 a, b, c;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + (length << 2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's */
    switch (length) {
        case 3:
            c += k[2];
            fallthrough;
        case 2:
            b += k[1];
            fallthrough;
        case 1:
            a += k[0];
            __jhash_final(a, b, c);
            break;
        case 0: /* Nothing left to add */
            break;
    }

    return c;
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval) {
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval) {
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval) {
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval) {
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif /* __MODULE_OVS_JHASH_ */
