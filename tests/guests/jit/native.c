#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* Native x86-64 observations precede JIT translation. Arithmetic flag masks
 * exclude undefined/reserved bits; MOV/SSE/RET do not define arithmetic flags. */
struct instruction_case {
    const char *name;
    const unsigned char *code;
    size_t size;
    uint64_t input;
    uint64_t flag_mask;
    int mode;
};
static const unsigned char move[] = {0x48,0xb8,0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0xc3};
static const unsigned char add[] = {0x48,0x83,0xc0,0x01,0xc3};
static const unsigned char sub[] = {0x48,0x83,0xe8,0x01,0xc3};
static const unsigned char jne[] = {0x48,0x83,0xf8,0x07,0x75,0x06,0xb8,0x2a,0x00,0x00,0x00,0xc3,0xb8,0x09,0x00,0x00,0x00,0xc3};
static const unsigned char je[] = {0x48,0x83,0xf8,0x07,0x74,0x06,0xb8,0x2a,0x00,0x00,0x00,0xc3,0xb8,0x09,0x00,0x00,0x00,0xc3};
static const unsigned char memory[] = {0x48,0x89,0x07,0x48,0x83,0x07,0x05,0x48,0x8b,0x07,0xc3};
static const unsigned char fallback[] = {0x66,0x0f,0xef,0xc0,0x66,0x48,0x0f,0x7e,0xc0,0xc3};
static const unsigned char fault[] = {0x48,0x8b,0x07,0xc3};
static const unsigned char divide[] = {0x31,0xd2,0x31,0xc9,0x48,0xf7,0xf1,0xc3};
static const struct instruction_case cases[] = {
    {"move64",move,sizeof(move),0,0,0},
    {"add64-carry",add,sizeof(add),UINT64_MAX,0x8d5,0},
    {"sub64-overflow",sub,sizeof(sub),UINT64_C(0x8000000000000000),0x8d5,0},
    {"jne-zf1-not-taken",jne,sizeof(jne),7,0x8d5,0},
    {"jne-zf0-taken",jne,sizeof(jne),8,0x8d5,0},
    {"je-zf1-taken",je,sizeof(je),7,0x8d5,0},
    {"je-zf0-not-taken",je,sizeof(je),8,0x8d5,0},
    {"memory-read-write",memory,sizeof(memory),11,0x8d5,0},
    {"unsupported-sse-fallback",fallback,sizeof(fallback),17,0,0},
    {"unmapped-data-fault",fault,sizeof(fault),0,0,1},
    {"division-fault",divide,sizeof(divide),1,0,0},
    {"self-modifying-code",move,sizeof(move),0,0,2},
    {"cross-page-instruction",move,sizeof(move),0,0,3},
};

static void observe(const struct instruction_case *item) {
    unsigned char *mapping = mmap(NULL,8192,PROT_READ|PROT_WRITE|PROT_EXEC,
                                  MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    uint64_t *data = mmap(NULL,4096,PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (mapping == MAP_FAILED || data == MAP_FAILED) _exit(110);
    unsigned char *entry = mapping + (item->mode == 3 ? 4093 : 0);
    memcpy(entry,item->code,item->size);
    if (item->mode == 1 && mprotect(data,4096,PROT_NONE)) _exit(111);
    uint64_t value = item->input, flags;
    __asm__ volatile("call *%[entry]; pushfq; pop %[flags]"
        : "+a"(value), [flags]"=r"(flags)
        : [entry]"r"(entry), "D"(data)
        : "rcx","rdx","rsi","r8","r9","r10","r11","xmm0","cc","memory");
    uint64_t first = value;
    if (item->mode == 2) {
        entry[2] = 0x2a;
        memset(entry+3,0,7);
        __asm__ volatile("call *%[entry]" : "+a"(value)
            : [entry]"r"(entry), "D"(data)
            : "rcx","rdx","rsi","r8","r9","r10","r11","xmm0","cc","memory");
    }
    printf("{\"name\":\"%s\",\"rax\":\"%016" PRIx64 "\",\"first_rax\":\"%016" PRIx64
           "\",\"flags\":\"%016" PRIx64 "\",\"flag_mask\":\"%016" PRIx64
           "\",\"memory\":\"%016" PRIx64 "\",\"signal\":0,\"child_exit\":0}\n",
           item->name,value,first,flags & item->flag_mask,item->flag_mask,*data);
    fflush(stdout);
    _exit(0);
}

/* Integer-SSE register forms (Loop-back 1 Step32): every operand is an XMM
 * register. The trampoline loads RFLAGS, XMM0-15 and every GPR except RSP from
 * `in`, calls the case, and stores the same registers to `out`. RSP is an
 * address that differs per run, so it is neither loaded nor observed. A case
 * holds exactly one 0xc3 byte, its final RET, so returning proves that RIP
 * reached that RET; `rip` is that byte's offset. None of these SSE forms
 * defines arithmetic flags; only the loop's SUB writes them. */
struct sse_state {
    uint64_t gpr[16];    /* x86 encoding order: rax rcx rdx rbx rsp rbp rsi rdi r8-r15 */
    uint64_t flags;
    uint64_t reserved;
    uint64_t xmm[16][2]; /* [0] = bits 0-63, [1] = bits 64-127 */
};
_Static_assert(offsetof(struct sse_state, flags) == 128, "flags offset");
_Static_assert(offsetof(struct sse_state, xmm) == 144, "xmm offset");
_Static_assert(sizeof(struct sse_state) == 400, "state size");
#define SSE_FLAG_MASK UINT64_C(0x8d5)

void jit_sse_trampoline(const struct sse_state *in, struct sse_state *out,
                        const unsigned char *entry);
__asm__(
    ".text\n"
    ".globl jit_sse_trampoline\n"
    ".type jit_sse_trampoline,@function\n"
    "jit_sse_trampoline:\n"
    "  push %rbx\n  push %rbp\n  push %r12\n  push %r13\n  push %r14\n  push %r15\n"
    "  push %rsi\n" /* out */
    "  push %rdx\n" /* entry */
    "  movdqu 144(%rdi),%xmm0\n  movdqu 160(%rdi),%xmm1\n"
    "  movdqu 176(%rdi),%xmm2\n  movdqu 192(%rdi),%xmm3\n"
    "  movdqu 208(%rdi),%xmm4\n  movdqu 224(%rdi),%xmm5\n"
    "  movdqu 240(%rdi),%xmm6\n  movdqu 256(%rdi),%xmm7\n"
    "  movdqu 272(%rdi),%xmm8\n  movdqu 288(%rdi),%xmm9\n"
    "  movdqu 304(%rdi),%xmm10\n  movdqu 320(%rdi),%xmm11\n"
    "  movdqu 336(%rdi),%xmm12\n  movdqu 352(%rdi),%xmm13\n"
    "  movdqu 368(%rdi),%xmm14\n  movdqu 384(%rdi),%xmm15\n"
    "  pushq 128(%rdi)\n  popfq\n"
    "  mov 0(%rdi),%rax\n  mov 8(%rdi),%rcx\n  mov 16(%rdi),%rdx\n  mov 24(%rdi),%rbx\n"
    "  mov 40(%rdi),%rbp\n  mov 48(%rdi),%rsi\n"
    "  mov 64(%rdi),%r8\n  mov 72(%rdi),%r9\n  mov 80(%rdi),%r10\n  mov 88(%rdi),%r11\n"
    "  mov 96(%rdi),%r12\n  mov 104(%rdi),%r13\n  mov 112(%rdi),%r14\n  mov 120(%rdi),%r15\n"
    "  mov 56(%rdi),%rdi\n"
    "  call *(%rsp)\n"
    "  pushfq\n  push %rdi\n"
    "  mov 24(%rsp),%rdi\n" /* stack: guest rdi, flags, entry, out */
    "  mov %rax,0(%rdi)\n  mov %rcx,8(%rdi)\n  mov %rdx,16(%rdi)\n  mov %rbx,24(%rdi)\n"
    "  movq $0,32(%rdi)\n  mov %rbp,40(%rdi)\n  mov %rsi,48(%rdi)\n"
    "  mov %r8,64(%rdi)\n  mov %r9,72(%rdi)\n  mov %r10,80(%rdi)\n  mov %r11,88(%rdi)\n"
    "  mov %r12,96(%rdi)\n  mov %r13,104(%rdi)\n  mov %r14,112(%rdi)\n  mov %r15,120(%rdi)\n"
    "  pop %rax\n  mov %rax,56(%rdi)\n"
    "  pop %rax\n  mov %rax,128(%rdi)\n"
    "  movdqu %xmm0,144(%rdi)\n  movdqu %xmm1,160(%rdi)\n"
    "  movdqu %xmm2,176(%rdi)\n  movdqu %xmm3,192(%rdi)\n"
    "  movdqu %xmm4,208(%rdi)\n  movdqu %xmm5,224(%rdi)\n"
    "  movdqu %xmm6,240(%rdi)\n  movdqu %xmm7,256(%rdi)\n"
    "  movdqu %xmm8,272(%rdi)\n  movdqu %xmm9,288(%rdi)\n"
    "  movdqu %xmm10,304(%rdi)\n  movdqu %xmm11,320(%rdi)\n"
    "  movdqu %xmm12,336(%rdi)\n  movdqu %xmm13,352(%rdi)\n"
    "  movdqu %xmm14,368(%rdi)\n  movdqu %xmm15,384(%rdi)\n"
    "  add $16,%rsp\n"
    "  pop %r15\n  pop %r14\n  pop %r13\n  pop %r12\n  pop %rbp\n  pop %rbx\n"
    "  ret\n"
    ".size jit_sse_trampoline,.-jit_sse_trampoline\n");

struct sse_case {
    const char *name;
    const unsigned char *code;
    size_t size;
    uint64_t flags;
    uint64_t xmm0[2];
    uint64_t xmm1[2];
};
/* pshufd xmm0,xmm1,imm; the 0x1b case also uses REX (pshufd xmm9,xmm14). */
static const unsigned char pshufd_00[] = {0x66,0x0f,0x70,0xc1,0x00,0xc3};
static const unsigned char pshufd_1b[] = {0x66,0x0f,0x70,0xc1,0x1b,0x66,0x45,0x0f,0x70,0xce,0x1b,0xc3};
static const unsigned char pshufd_b1[] = {0x66,0x0f,0x70,0xc1,0xb1,0xc3};
static const unsigned char pshufd_e4[] = {0x66,0x0f,0x70,0xc1,0xe4,0xc3};
static const unsigned char pmuludq[] = {0x66,0x0f,0xf4,0xc1,0xc3};
static const unsigned char paddd[] = {0x66,0x0f,0xfe,0xc1,0xc3};
static const unsigned char psubd[] = {0x66,0x0f,0xfa,0xc1,0xc3};
/* pslld xmm0..xmm4 by 0/1/31/32/255, then pslld xmm12,31. */
static const unsigned char pslld[] = {0x66,0x0f,0x72,0xf0,0x00, 0x66,0x0f,0x72,0xf1,0x01,
    0x66,0x0f,0x72,0xf2,0x1f, 0x66,0x0f,0x72,0xf3,0x20, 0x66,0x0f,0x72,0xf4,0xff,
    0x66,0x41,0x0f,0x72,0xf4,0x1f, 0xc3};
/* psrld xmm0..xmm4 by 0/1/31/32/255, then psrld xmm13,1. */
static const unsigned char psrld[] = {0x66,0x0f,0x72,0xd0,0x00, 0x66,0x0f,0x72,0xd1,0x01,
    0x66,0x0f,0x72,0xd2,0x1f, 0x66,0x0f,0x72,0xd3,0x20, 0x66,0x0f,0x72,0xd4,0xff,
    0x66,0x41,0x0f,0x72,0xd5,0x01, 0xc3};
static const unsigned char packuswb[] = {0x66,0x0f,0x67,0xc1,0xc3};
static const unsigned char punpckldq[] = {0x66,0x0f,0x62,0xc1,0xc3};
/* movdqa xmm0,xmm1 (6f); movdqa xmm2,xmm3 (7f register form); movdqa xmm9,xmm14. */
static const unsigned char movdqa[] = {0x66,0x0f,0x6f,0xc1, 0x66,0x0f,0x7f,0xda,
    0x66,0x45,0x0f,0x6f,0xce, 0xc3};
/* pxor xmm0,xmm1; por xmm2,xmm3; pand xmm4,xmm5; pxor xmm6,xmm6; pand xmm10,xmm15. */
static const unsigned char logic[] = {0x66,0x0f,0xef,0xc1, 0x66,0x0f,0xeb,0xd3,
    0x66,0x0f,0xdb,0xe5, 0x66,0x0f,0xef,0xf6, 0x66,0x45,0x0f,0xdb,0xd7, 0xc3};
/* mov ecx,4; loop: paddd xmm0,xmm1; pshufd xmm1,xmm1,0x93; pmuludq xmm3,xmm1;
 * psrld xmm3,3; pxor xmm2,xmm0; sub ecx,1; jnz loop; ret. */
static const unsigned char sse_loop[] = {0xb9,0x04,0x00,0x00,0x00,
    0x66,0x0f,0xfe,0xc1, 0x66,0x0f,0x70,0xc9,0x93, 0x66,0x0f,0xf4,0xd9,
    0x66,0x0f,0x72,0xd3,0x03, 0x66,0x0f,0xef,0xd0, 0x83,0xe9,0x01, 0x75,0xe5, 0xc3};
#define SSE_CASE(name, code, flags, x0lo, x0hi, x1lo, x1hi) \
    {name, code, sizeof(code), flags, {UINT64_C(x0lo), UINT64_C(x0hi)}, {UINT64_C(x1lo), UINT64_C(x1hi)}}
static const struct sse_case sse_cases[] = {
    SSE_CASE("sse-pshufd-00", pshufd_00, 0x8d7, 0xa5a5a5a5a5a5a5a5, 0x5a5a5a5a5a5a5a5a,
             0x2222222211111111, 0x4444444433333333),
    SSE_CASE("sse-pshufd-1b", pshufd_1b, 0x002, 0xa5a5a5a5a5a5a5a5, 0x5a5a5a5a5a5a5a5a,
             0x2222222211111111, 0x4444444433333333),
    SSE_CASE("sse-pshufd-b1", pshufd_b1, 0x8d7, 0xa5a5a5a5a5a5a5a5, 0x5a5a5a5a5a5a5a5a,
             0x2222222211111111, 0x4444444433333333),
    SSE_CASE("sse-pshufd-e4", pshufd_e4, 0x002, 0xa5a5a5a5a5a5a5a5, 0x5a5a5a5a5a5a5a5a,
             0x2222222211111111, 0x4444444433333333),
    SSE_CASE("sse-pmuludq-max", pmuludq, 0x8d7, 0xffffffffffffffff, 0xffffffffffffffff,
             0xffffffffffffffff, 0xffffffffffffffff),
    SSE_CASE("sse-pmuludq-upper-ignored", pmuludq, 0x002, 0xdeadbeef00000003, 0x1234567800000005,
             0xcafebabe00000007, 0x876543210000000b),
    SSE_CASE("sse-paddd-wraparound", paddd, 0x8d7, 0xffffffff7fffffff, 0x8000000000000001,
             0x0000000100000001, 0x80000000ffffffff),
    SSE_CASE("sse-psubd-wraparound", psubd, 0x002, 0x0000000080000000, 0x000000017fffffff,
             0x0000000100000001, 0x00000002ffffffff),
    SSE_CASE("sse-pslld-counts", pslld, 0x8d7, 0x80000001ffffffff, 0x7fffffff00000001,
             0xfedcba9876543210, 0x0123456789abcdef),
    SSE_CASE("sse-psrld-counts", psrld, 0x002, 0x80000001ffffffff, 0x7fffffff00000001,
             0xfedcba9876543210, 0x0123456789abcdef),
    SSE_CASE("sse-packuswb-saturation", packuswb, 0x8d7, 0x7fff010000ff0000, 0x007f0080ffff8000,
             0x0001fffe010100fe, 0x80017ffe0000ff00),
    SSE_CASE("sse-punpckldq", punpckldq, 0x002, 0xa1a1a1a1b2b2b2b2, 0xc3c3c3c3d4d4d4d4,
             0x0f0f0f0ff0f0f0f0, 0x5555aaaa3333cccc),
    SSE_CASE("sse-movdqa-register", movdqa, 0x8d7, 0x0102030405060708, 0x090a0b0c0d0e0f10,
             0xffeeddccbbaa9988, 0x7766554433221100),
    SSE_CASE("sse-logic-register", logic, 0x002, 0xf0f0f0f0f0f0f0f0, 0xff00ff00ff00ff00,
             0x0ff00ff00ff00ff0, 0x00ff00ff00ff00ff),
    SSE_CASE("sse-jcc-loop", sse_loop, 0x8d7, 0x0000000000000001, 0x0000000000000002,
             0x0000000300000002, 0x0000000700000005),
};

static void sse_input(const struct sse_case *item, struct sse_state *in) {
    memset(in,0,sizeof *in);
    for (uint64_t index=0; index<16; index++) {
        if (index != 4) in->gpr[index] = UINT64_C(0x0123456789abcdef) ^ (UINT64_C(0x1111111111111111) * index);
        in->xmm[index][0] = UINT64_C(0x9e3779b97f4a7c15) * (2*index+1);
        in->xmm[index][1] = UINT64_C(0xc2b2ae3d27d4eb4f) * (2*index+2);
    }
    memcpy(in->xmm[0],item->xmm0,sizeof item->xmm0);
    memcpy(in->xmm[1],item->xmm1,sizeof item->xmm1);
    in->flags = item->flags;
}

static void print_sse_state(const struct sse_state *state, const char *gpr, const char *xmm) {
    printf(",\"%s\":[",gpr);
    for (size_t index=0; index<16; index++)
        printf("%s\"%016" PRIx64 "\"",index ? "," : "",state->gpr[index]);
    printf("],\"%s\":[",xmm);
    for (size_t index=0; index<16; index++)
        printf("%s\"%016" PRIx64 "%016" PRIx64 "\"",index ? "," : "",
               state->xmm[index][1],state->xmm[index][0]);
    printf("]");
}

static void observe_sse(const struct sse_case *item) {
    if (item->size == 0 || item->code[item->size-1] != 0xc3
            || memchr(item->code,0xc3,item->size-1) != NULL) _exit(120);
    unsigned char *mapping = mmap(NULL,4096,PROT_READ|PROT_WRITE|PROT_EXEC,
                                  MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (mapping == MAP_FAILED) _exit(121);
    memcpy(mapping,item->code,item->size);
    struct sse_state in, out;
    sse_input(item,&in);
    memset(&out,0,sizeof out);
    jit_sse_trampoline(&in,&out,mapping);
    printf("{\"name\":\"%s\",\"signal\":0,\"child_exit\":0,\"code\":\"",item->name);
    for (size_t index=0; index<item->size; index++) printf("%02x",item->code[index]);
    printf("\",\"in_flags\":\"%016" PRIx64 "\"",in.flags);
    print_sse_state(&in,"in_gpr","in_xmm");
    printf(",\"flags\":\"%016" PRIx64 "\",\"flag_mask\":\"%016" PRIx64 "\",\"rip\":\"%016" PRIx64 "\"",
           out.flags & SSE_FLAG_MASK,SSE_FLAG_MASK,(uint64_t)(item->size-1));
    print_sse_state(&out,"gpr","xmm");
    printf("}\n");
    fflush(stdout);
    _exit(0);
}

static int supervise(const char *name, const struct instruction_case *item,
                     const struct sse_case *sse) {
    pid_t child = fork();
    if (child < 0) return 113;
    if (child == 0) {
        if (sse) observe_sse(sse);
        else observe(item);
    }
    int status;
    if (waitpid(child,&status,0) != child) return 114;
    if (WIFSIGNALED(status)) {
        printf("{\"name\":\"%s\",\"signal\":%d,\"child_exit\":null}\n",name,WTERMSIG(status));
        fflush(stdout);
    } else if (!WIFEXITED(status) || WEXITSTATUS(status)) return 115;
    return 0;
}

int main(void) {
    struct rlimit limit = {0,0};
    if (setrlimit(RLIMIT_CORE,&limit)) return 112;
    for (size_t index=0; index<sizeof(cases)/sizeof(cases[0]); index++) {
        int failure = supervise(cases[index].name,&cases[index],NULL);
        if (failure) return failure;
    }
    for (size_t index=0; index<sizeof(sse_cases)/sizeof(sse_cases[0]); index++) {
        int failure = supervise(sse_cases[index].name,NULL,&sse_cases[index]);
        if (failure) return failure;
    }
    return 0;
}
