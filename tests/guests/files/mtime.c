/* Native-first signed Linux stat ABI oracle. argv[1] is a fixture file. */
static long call(long n, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return result;
}
void entry(long *stack) {
    const char *path = (const char *)stack[2];
    unsigned char st[144] = {0};
    long result[6] = {0};
    result[0] = call(4, (long)path, (long)st, 0);
    if (!result[0]) { result[1] = *(long *)(st + 88); result[2] = *(long *)(st + 96); }
    long fd = call(2, (long)path, 0, 0);
    result[3] = call(5, fd, (long)st, 0);
    if (!result[3]) { result[4] = *(long *)(st + 88); result[5] = *(long *)(st + 96); }
    call(3, fd, 0, 0);
    call(1, 1, (long)result, sizeof(result));
    call(60, 0, 0, 0);
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall entry\nud2\n");
