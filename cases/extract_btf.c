#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// 提取位字段的函数
uint64_t extract_bf(uint64_t val, bool has_sign, uint16_t bit_off, uint16_t bit_sz) {
    printf("%d\n", (64 - bit_sz) - (bit_off % 8));
    printf("%d\n", 64 - bit_sz);
    val <<= (64 - bit_sz) - (bit_off % 8);
    return has_sign ? (int64_t)val >> (64 - bit_sz) : val >> (64 - bit_sz);
}

int main() {
    // 模拟原始内存中的数据（1 字节）
    // 假设结构体被打包为一个字节，value = -1 (二进制为 11111), pad = 000
    // 最终 8 位应为 11111000，即 0xF8
   const uint8_t raw = 0xF8;

    // 提取从 bit 3 开始的 5 位字段
    const uint64_t val = raw;                            // 先扩展为 64 位，准备提取
   const int64_t result = extract_bf(val, false, 3, 5); // 从 bit 3 提取 5 位，保留符号

    printf("原始字节: 0x%02x\n", raw);
    printf("提取结果: %ld (十六进制: 0x%lx)\n", result, result);

    return 0;
}
