/* Reuse the exact instruction fixture, but drive its frame calls from seven
 * caller stack placements. This guest never executes an unsafe old LEAVE. */
#define test_main frame_full_test_main
#include "forms-frame.c"
#undef test_main

static u8 caller_stack[3 * 65536] __attribute__((aligned(65536), used));
extern void frame_at_stack(void (*function)(u64 *), u64 *, u8 *);
__asm__(".text\n.global frame_at_stack\nframe_at_stack:\n"
        "pushq %rbp\n pushq %r12\n pushq %r13\n pushq %r14\n pushq %r15\n"
        "movq %rsp,%r12\n movq %rdi,%r13\n movq %rsi,%r14\n movq %rdx,%r15\n"
        "movabsq $0x1122334455667788,%rbp\n movq %r15,%rsp\n"
        "movq %r14,%rdi\n call *%r13\n"
        "movq %rsp,%rax\n subq %r15,%rax\n movq %rax,24(%r14)\n"
        "movabsq $0x1122334455667788,%rax\n xorq %rbp,%rax\n movq %rax,32(%r14)\n"
        "movq %r12,%rsp\n popq %r15\n popq %r14\n popq %r13\n popq %r12\n popq %rbp\n ret\n");

int test_main(void) {
    const u64 frame_base = (u64)frame_stack;
    const u64 frame_top = frame_base + 32768 - 1024;
    /* Validate the placement assumption before using the shared frame code. */
    if ((frame_base & 0xffff) != 0 || (frame_top & 0xffff) != 0x7c00 ||
        ((frame_top - 64 - 24) >> 16) != (frame_base >> 16) ||
        ((frame_top + 512) >> 16) != (frame_base >> 16)) {
        return 2;
    }
    report_value("scratch-low16", frame_top & 0xffff);
    const u64 placements[] = {0, 1, 2, 0x1ff, 0xfdff, 0xfe00, 0xffff};
    void (*functions[])(u64 *) = {w0, w1, w2, w31, lw, ew42, ew43};
    const u64 nesting[] = {0, 1, 2, 31, 2, 2, 2};
    for (u64 placement = 0; placement < 7; placement++) {
        const u64 caller = (u64)(caller_stack + 65536 + placements[placement]);
        const u64 original_frame_top = caller - 8 - 8 - 1024;
        /* Describe the original placement arithmetically; do not execute it. */
        report_value("old-frame-window-mismatch",
                     ((original_frame_top + 512) >> 16) !=
                     ((original_frame_top - 2) >> 16));
        for (u64 function = 0; function < 7; function++) {
            u64 result[5] = {0};
            /* Every old caller placement is mapped on both sides. */
            frame_at_stack(functions[function], result,
                           caller_stack + 65536 + placements[placement]);
            const u64 expected_rsp = function == 4 ? 0 :
                0UL - 24 - 2 * (nesting[function] ? nesting[function] + 1 : 1);
            const u64 expected_rbp = function == 4 ? 512 : 0UL - 2;
            report_value("caller-low16", placements[placement]);
            report_value("frame-kind", function);
            report_value("frame-rsp", result[0]);
            report_value("frame-rbp", result[1]);
            report_value("caller-rsp-delta", result[3]);
            report_value("caller-rbp-xor", result[4]);
            if (result[0] != expected_rsp || result[1] != expected_rbp ||
                result[3] != 0 || result[4] != 0) {
                flush_out();
                return 1;
            }
        }
    }
    flush_out();
    return 0;
}
