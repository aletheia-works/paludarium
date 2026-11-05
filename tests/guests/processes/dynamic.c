/* A dynamically linked program, on musl's dynamic linker or glibc's. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <unistd.h>

/* What differs with the libc it is built for. */
#ifndef PLUGIN_NAME
#define PLUGIN_NAME "dynamic-plugin.so"
#endif

extern char **environ;
extern void _start(void);
extern char __executable_start;
static __thread int local = 5;

/* The program and libc; Linux also gives a vDSO, which the emulator has not. */
static int objects;
static int count_object(struct dl_phdr_info *info, size_t size, void *unused) {
    (void)size;
    (void)unused;
    objects += info->dlpi_phnum > 0;
    return 0;
}
static void *in_thread(void *unused) {
    (void)unused;
    local += 1;
    return (void *)(intptr_t)local;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    /* What the exec cases look at. */
    if (!strcmp(mode, "dynamic-ids")) {
        printf("  ran: argc=%d uid=%d euid=%d secure=%lu dumpable=%d\n", argc, (int)getuid(), (int)geteuid(),
               getauxval(AT_SECURE), prctl(PR_GET_DUMPABLE) == 1);
        return 0;
    }
    printf("argc=%d", argc);
    for (int i = 1; i < argc - 1; i++) printf(" [%s]", argv[i]);
    printf("\n");
    /* The auxiliary vector. */
    unsigned long base = getauxval(AT_BASE), phdr = getauxval(AT_PHDR);
    printf("base-set=%d base-aligned=%d\n", base != 0, base % 4096 == 0);
    printf("entry-is-start=%d\n", getauxval(AT_ENTRY) == (unsigned long)&_start);
    printf("phdr-in-program=%d phent=%lu\n",
           phdr >= (unsigned long)&__executable_start && phdr < (unsigned long)&__executable_start + 4096,
           getauxval(AT_PHENT));
    printf("break-after-program=%d\n", (unsigned long)sbrk(0) > (unsigned long)&__executable_start);
    /* What the linker did. */
    printf("relocated: %s %d\n", getenv("NOTHING_HERE") ? "set" : "unset", (int)strlen("twelve bytes"));
    char *block = malloc(1 << 20);
    printf("malloc=%d\n", block != NULL);
    /* Large enough for libc's own way of copying much, whatever its size is
       on this CPU, in both directions. */
    if (!block) return 84;
    for (size_t i = 0; i < 1 << 20; i++) block[i] = (char)(i * 31 >> 3);
    char *copy = malloc((1 << 20) + 4096);
    if (!copy) return 85;
    memcpy(copy, block, 1 << 20);
    printf("copied=%d\n", !memcmp(copy, block, 1 << 20));
    memmove(copy + 4096, copy, 1 << 20);
    printf("moved=%d\n", !memcmp(copy + 4096, block, 1 << 20));
    free(copy);
    free(block);
    dl_iterate_phdr(count_object, NULL);
    printf("objects=%d\n", objects >= 2);
    printf("local=%d\n", local);
    pthread_t thread;
    void *from_thread = NULL;
    if (pthread_create(&thread, NULL, in_thread, NULL) || pthread_join(thread, &from_thread)) return 80;
    printf("thread-local=%d main-local=%d\n", (int)(intptr_t)from_thread, local);
    /* Loading more. */
    printf("own-symbol=%d\n", dlsym(RTLD_DEFAULT, "strlen") != NULL);
    printf("missing-symbol=%d\n", dlsym(RTLD_DEFAULT, "no_such_symbol") != NULL);
    void *none = dlopen("./no-such-library.so", RTLD_NOW);
    printf("missing-library=%d\n", none != NULL);
    char path[PATH_MAX];
    strncpy(path, argv[argc - 1], sizeof path - 32);
    path[sizeof path - 32] = 0;
    char *slash = strrchr(path, '/');
    if (!slash) return 81;
    strcpy(slash + 1, PLUGIN_NAME);
    void *plugin = dlopen(path, RTLD_NOW);
    if (!plugin) {
        printf("dlopen: failed\n");
        return 82;
    }
    int (*value)(int) = (int (*)(int))dlsym(plugin, "plugin_value");
    printf("plugin-symbol=%d\n", value != NULL);
    if (!value) return 83;
    fflush(stdout);
    printf("value=%d\n", value(2));
    fflush(stdout);
    pthread_t second;
    (void)second;
    printf("closed=%d\n", dlclose(plugin));
    return 7;
}
