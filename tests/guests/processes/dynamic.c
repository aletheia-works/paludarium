/* A dynamically linked program, on musl's dynamic linker or glibc's. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
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
/* Whether the VMA at `address` in /proc/self/maps is named by a path. */
static int in_maps(unsigned long address) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[PATH_MAX + 128];
    int named = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2 && start <= address && address < end) {
            named = strchr(line, '/') != NULL;
            break;
        }
    }
    fclose(maps);
    return named;
}

static pthread_mutex_t robust_mutex;
static void *robust_owner(void *unused) {
    (void)unused;
    pthread_mutex_lock(&robust_mutex);
    return NULL;
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
    printf("linker-in-maps=%d\n", in_maps(getauxval(AT_BASE)));
    printf("program-in-maps=%d\n", in_maps((unsigned long)&__executable_start));
    /* What the linker did. */
    printf("relocated: %s %d\n", getenv("NOTHING_HERE") ? "set" : "unset", (int)strlen("twelve bytes"));
#ifdef __GLIBC__
    /* Through the x87: glibc's printf takes these as long doubles. */
    printf("floats: %.3f %Lf\n", 1.5, (long double)2.25);
#endif
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
    /* A robust mutex, whose owner ends holding it. */
    pthread_mutexattr_t attributes_robust;
    pthread_mutexattr_init(&attributes_robust);
    printf("robust-attribute=%d\n", pthread_mutexattr_setrobust(&attributes_robust, PTHREAD_MUTEX_ROBUST));
    if (pthread_mutex_init(&robust_mutex, &attributes_robust)) return 86;
    pthread_t owner;
    if (pthread_create(&owner, NULL, robust_owner, NULL) || pthread_join(owner, NULL)) return 87;
    int locked = pthread_mutex_lock(&robust_mutex);
    printf("owner-dead=%d\n", locked == EOWNERDEAD);
    printf("consistent=%d\n", pthread_mutex_consistent(&robust_mutex));
    printf("unlocked=%d\n", pthread_mutex_unlock(&robust_mutex));
    printf("relocked=%d\n", pthread_mutex_lock(&robust_mutex));
#ifdef __GLIBC__
    /* glibc finds the main thread's stack in /proc/self/maps. */
    pthread_attr_t attributes;
    void *stack = NULL;
    size_t stack_size = 0;
    int found = pthread_getattr_np(pthread_self(), &attributes);
    if (!found) found = pthread_attr_getstack(&attributes, &stack, &stack_size);
    char *here = (char *)&attributes;
    printf("main-stack: found=%d holds-this=%d\n", found == 0,
           here >= (char *)stack && here < (char *)stack + stack_size);
#endif
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
