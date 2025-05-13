#include <bpf/bpf_helpers.h>
#include <vmlinux.h>

#include <common.h>

// 将这些值设置为每个对象的独立值是安全的，因为加载的对象不会在关联的程序之间共享以用于原始跟踪点。
const volatile u64 ksym = 0;
const volatile u32 nargs = 0;

/* We unroll the loop bellow as the verifier disallow arithmetic operations on
 * context pointer. The loop unrolling pragma doesn't work here, do it manually,
 * keeping the "dynamic" fashion.
 */
static __always_inline void get_regs(struct retis_regs *regs, struct bpf_raw_tracepoint_args *ctx) {
    if (!nargs)
        return;

    switch (nargs - 1) {
        case 11:
            regs->reg[11] = ctx->args[11];
        case 10:
            regs->reg[10] = ctx->args[10];
        case 9:
            regs->reg[9] = ctx->args[9];
        case 8:
            regs->reg[8] = ctx->args[8];
        case 7:
            regs->reg[7] = ctx->args[7];
        case 6:
            regs->reg[6] = ctx->args[6];
        case 5:
            regs->reg[5] = ctx->args[5];
        case 4:
            regs->reg[4] = ctx->args[4];
        case 3:
            regs->reg[3] = ctx->args[3];
        case 2:
            regs->reg[2] = ctx->args[2];
        case 1:
            regs->reg[1] = ctx->args[1];
        case 0:
            regs->reg[0] = ctx->args[0];
        default:
    }

    regs->num = nargs;
}

SEC("raw_tracepoint/probe")
int probe_raw_tracepoint(struct bpf_raw_tracepoint_args *ctx) {
    struct retis_context context = {};

    context.timestamp = bpf_ktime_get_ns();
    context.ksym = ksym;
    context.probe_type = KERNEL_PROBE_TRACEPOINT;
    context.orig_ctx = ctx;
    get_regs(&context.regs, ctx);

    return chain(&context);
}

char __license[] SEC("license") = "GPL";
