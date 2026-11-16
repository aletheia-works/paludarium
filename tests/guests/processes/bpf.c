/* bpf, compared with Linux, for its maps: the checks of every command,
   BPF_MAP_CREATE of arrays and hashes with its errors, the elements
   (lookup, update, delete, next key, lookup and delete), freezing, the
   batch commands, BPF_OBJ_GET_INFO_BY_FD, fdinfo, and the rule that keeps
   a user without CAP_BPF out (kernel.unprivileged_bpf_disabled, 2).

   The map IDs (BPF_MAP_GET_NEXT_ID, BPF_MAP_GET_FD_BY_ID) are compared by
   what they find, and the memory fdinfo gives a map (memlock), with the
   ENOMEM of a map larger than any machine, as the CI machines' kernel
   (Ubuntu's Linux 7.0) counts it.

   A hash's keys come in an order of its buckets, which a random seed
   picks: they are given sorted. The IDs themselves, which other maps on
   the machine move, the memory of a preallocated hash, which counts the
   possible CPUs, but for its difference between sizes, and the size Linux
   knows of its union are not printed. Programs, BTF and links are not
   used. The cases run as root, as the guest does. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAP_CREATE 0
#define MAP_LOOKUP_ELEM 1
#define MAP_UPDATE_ELEM 2
#define MAP_DELETE_ELEM 3
#define MAP_GET_NEXT_KEY 4
#define MAP_GET_NEXT_ID 12
#define MAP_GET_FD_BY_ID 14
#define OBJ_GET_INFO_BY_FD 15
#define MAP_LOOKUP_AND_DELETE_ELEM 21
#define MAP_FREEZE 22
#define MAP_LOOKUP_BATCH 24
#define MAP_LOOKUP_AND_DELETE_BATCH 25
#define MAP_UPDATE_BATCH 26
#define MAP_DELETE_BATCH 27

#define TYPE_HASH 1
#define TYPE_ARRAY 2

#define F_NO_PREALLOC (1 << 0)
#define F_NO_COMMON_LRU (1 << 1)
#define F_NUMA_NODE (1 << 2)
#define F_RDONLY (1 << 3)
#define F_WRONLY (1 << 4)
#define F_ZERO_SEED (1 << 6)
#define F_RDONLY_PROG (1 << 7)
#define F_WRONLY_PROG (1 << 8)
#define F_MMAPABLE (1 << 10)
#define F_PRESERVE_ELEMS (1 << 11)

#define ANY 0
#define NOEXIST 1
#define EXIST 2
#define ELEM_F_LOCK 4

/* The part of union bpf_attr the cases use, 128 bytes, which every kernel
   the tests run on knows. */
union attr {
    struct {
        uint32_t map_type, key_size, value_size, max_entries, map_flags, inner_map_fd, numa_node;
        char map_name[16];
        uint32_t map_ifindex, btf_fd, btf_key_type_id, btf_value_type_id, btf_vmlinux_value_type_id;
        uint64_t map_extra;
    };
    struct {
        uint32_t map_fd;
        uint64_t key, value, flags;
    } elem;
    struct {
        uint64_t in_batch, out_batch, keys, values;
        uint32_t count, map_fd;
        uint64_t elem_flags, flags;
    } batch;
    struct {
        uint32_t bpf_fd, info_len;
        uint64_t info;
    } info;
    struct {
        uint32_t start_id, next_id, open_flags;
    } id;
    unsigned char bytes[128];
};

struct map_info {
    uint32_t type, id, key_size, value_size, max_entries, map_flags;
    char name[16];
    uint32_t ifindex, btf_vmlinux_value_type_id;
    uint64_t netns_dev, netns_ino;
    uint32_t btf_id, btf_key_type_id, btf_value_type_id, btf_vmlinux_id;
    uint64_t map_extra;
};

static void say(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
    putchar('\n');
    fflush(stdout);
}

#define TRY(call) ({ long try_result = (call); try_result < 0 ? -errno : try_result; })

static long bpf(int cmd, void *attr, unsigned size) {
    long result = syscall(SYS_bpf, cmd, attr, size);
    return result < 0 ? -errno : result;
}

static union attr map_attr(uint32_t type, uint32_t key, uint32_t value, uint32_t entries, uint32_t flags) {
    union attr a;
    memset(&a, 0, sizeof a);
    a.map_type = type;
    a.key_size = key;
    a.value_size = value;
    a.max_entries = entries;
    a.map_flags = flags;
    return a;
}

/* A map create that should fail: an fd is closed and shown as "fd". */
static void create(const char *name, union attr a) {
    long fd = bpf(MAP_CREATE, &a, sizeof a);
    if (fd >= 0) {
        close((int)fd);
        say("%s fd", name);
    } else {
        say("%s %ld", name, fd);
    }
}

static int make(uint32_t type, uint32_t key, uint32_t value, uint32_t entries, uint32_t flags) {
    union attr a = map_attr(type, key, value, entries, flags);
    long fd = bpf(MAP_CREATE, &a, sizeof a);
    if (fd < 0) {
        say("make %ld", fd);
        exit(1);
    }
    return (int)fd;
}

static long elem(int cmd, int fd, const void *key, void *value, uint64_t flags) {
    union attr a;
    memset(&a, 0, sizeof a);
    a.elem.map_fd = (uint32_t)fd;
    a.elem.key = (uintptr_t)key;
    a.elem.value = (uintptr_t)value;
    a.elem.flags = flags;
    return bpf(cmd, &a, sizeof a);
}

static int compare(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

/* A hash's keys, from MAP_GET_NEXT_KEY, sorted. */
static void keys(const char *name, int fd) {
    uint32_t found[32], key, next;
    int n = 0;
    long r = elem(MAP_GET_NEXT_KEY, fd, NULL, &next, 0);
    while (r == 0 && n < 32) {
        found[n++] = next;
        key = next;
        r = elem(MAP_GET_NEXT_KEY, fd, &key, &next, 0);
    }
    qsort(found, (size_t)n, sizeof found[0], compare);
    printf("%s end %ld keys", name, r);
    for (int i = 0; i < n; i++) printf(" %u", found[i]);
    putchar('\n');
    fflush(stdout);
}

static int case_calls(void) {
    union attr a = map_attr(TYPE_ARRAY, 4, 8, 4, 0);
    say("unknown command %ld", bpf(1000, &a, sizeof a));
    say("fault %ld", bpf(MAP_CREATE, NULL, sizeof a));
    say("size past a page %ld", bpf(MAP_CREATE, &a, 4097));
    unsigned char big[256];
    memset(big, 0, sizeof big);
    memcpy(big, &a, sizeof a);
    long fd = bpf(MAP_CREATE, big, 200);
    say("size 200 zero tail %s", fd >= 0 ? "fd" : "error");
    if (fd >= 0) close((int)fd);
    big[199] = 1;
    say("size 200 tail %ld", bpf(MAP_CREATE, big, 200));
    say("size 4 %ld", bpf(MAP_CREATE, &a, 4));

    create("unspecified type", map_attr(0, 4, 8, 4, 0));
    create("unknown type", map_attr(1000, 4, 8, 4, 0));
    create("array key 8", map_attr(TYPE_ARRAY, 8, 8, 4, 0));
    create("array value 0", map_attr(TYPE_ARRAY, 4, 0, 4, 0));
    create("array entries 0", map_attr(TYPE_ARRAY, 4, 8, 0, 0));
    create("array unknown flag", map_attr(TYPE_ARRAY, 4, 8, 4, 1 << 20));
    create("array no prealloc", map_attr(TYPE_ARRAY, 4, 8, 4, 1));
    create("array preserve", map_attr(TYPE_ARRAY, 4, 8, 4, F_PRESERVE_ELEMS));
    create("both prog access", map_attr(TYPE_ARRAY, 4, 8, 4, F_RDONLY_PROG | F_WRONLY_PROG));
    create("both access", map_attr(TYPE_ARRAY, 4, 8, 4, F_RDONLY | F_WRONLY));
    a = map_attr(TYPE_ARRAY, 4, 8, 4, F_NUMA_NODE);
    a.numa_node = 5000;
    create("numa node", a);
    a = map_attr(TYPE_ARRAY, 4, 8, 4, 0);
    a.map_extra = 1;
    create("extra", a);
    a = map_attr(TYPE_ARRAY, 4, 8, 4, 0);
    strcpy(a.map_name, "a-b");
    create("name with dash", a);
    memcpy(a.map_name, "0123456789abcdef", 16);
    create("name of 16", a);
    strcpy(a.map_name, "map_1.x");
    create("name", a);
    a = map_attr(TYPE_ARRAY, 4, 8, 4, 0);
    a.btf_key_type_id = 1;
    create("btf key only", a);
    a.btf_value_type_id = 1;
    a.btf_fd = (uint32_t)open("/dev/null", O_RDONLY);
    create("btf of a file", a);
    close((int)a.btf_fd);
    a = map_attr(TYPE_ARRAY, 4, 8, 4, 0);
    a.btf_vmlinux_value_type_id = 1;
    create("vmlinux value", a);
    create("hash key 0", map_attr(TYPE_HASH, 0, 8, 4, 0));
    create("hash value 0", map_attr(TYPE_HASH, 4, 0, 4, 0));
    create("hash entries 0", map_attr(TYPE_HASH, 4, 8, 0, 0));
    create("hash no common lru", map_attr(TYPE_HASH, 4, 8, 4, F_NO_COMMON_LRU));
    create("hash mmapable", map_attr(TYPE_HASH, 4, 8, 4, 1 << 10));
    create("hash zero seed", map_attr(TYPE_HASH, 4, 8, 4, F_ZERO_SEED));
    create("hash too big", map_attr(TYPE_HASH, 4, 1 << 22, 4, 0));
    create("hash", map_attr(TYPE_HASH, 4, 8, 4, 0));

    /* The descriptor. */
    int map = make(TYPE_ARRAY, 4, 8, 4, 0);
    say("cloexec %d access %d", (fcntl(map, F_GETFD) & FD_CLOEXEC) != 0, fcntl(map, F_GETFL) & O_ACCMODE);
    char path[64], link[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", map);
    ssize_t length = readlink(path, link, sizeof link - 1);
    link[length < 0 ? 0 : length] = 0;
    say("link %s", link);
    char buffer[8];
    say("read %ld write %ld", TRY(read(map, buffer, 8)), TRY(write(map, buffer, 8)));
    int readonly = make(TYPE_ARRAY, 4, 8, 4, F_RDONLY);
    int writeonly = make(TYPE_ARRAY, 4, 8, 4, F_WRONLY);
    say("access read only %d write only %d", fcntl(readonly, F_GETFL) & O_ACCMODE, fcntl(writeonly, F_GETFL) & O_ACCMODE);

    /* The fdinfo, but for memlock and map_id. */
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", map);
    FILE *info = fopen(path, "r");
    char line[128];
    while (fgets(line, sizeof line, info)) {
        if (!strncmp(line, "map_", 4) && strncmp(line, "map_id", 6)) fputs(line, stdout);
        if (!strncmp(line, "key_size", 8) || !strncmp(line, "value_size", 10) ||
            !strncmp(line, "max_entries", 11) || !strncmp(line, "frozen", 6))
            fputs(line, stdout);
    }
    fclose(info);
    fflush(stdout);

    /* BPF_OBJ_GET_INFO_BY_FD, up to map_extra. */
    struct map_info mi;
    memset(&mi, 0, sizeof mi);
    a = map_attr(TYPE_HASH, 4, 8, 7, 0);
    strcpy(a.map_name, "named");
    int named = (int)bpf(MAP_CREATE, &a, sizeof a);
    union attr q;
    memset(&q, 0, sizeof q);
    q.info.bpf_fd = (uint32_t)named;
    q.info.info_len = sizeof mi;
    q.info.info = (uintptr_t)&mi;
    long r = bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q);
    say("info %ld len %u type %u key %u value %u entries %u flags %u name %s id %d", r, q.info.info_len, mi.type,
        mi.key_size, mi.value_size, mi.max_entries, mi.map_flags, mi.name, mi.id > 0);
    q.info.info_len = 8;
    memset(&mi, 0, sizeof mi);
    r = bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q);
    say("short info %ld len %u type %u key %u", r, q.info.info_len, mi.type, mi.key_size);
    q.info.bpf_fd = 999;
    say("info of no fd %ld", bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q));
    q.info.bpf_fd = 0;
    say("info of a file %ld", bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q));
    q.info.bpf_fd = (uint32_t)named;
    q.bytes[20] = 1;
    say("info with more %ld", bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q));
    close(named);
    close(readonly);
    close(writeonly);
    close(map);
    return 0;
}

static int case_elements(void) {
    int array = make(TYPE_ARRAY, 4, 8, 4, 0);
    uint32_t key = 1;
    uint64_t value = 0x1122334455667788, got = 0;
    long r = elem(MAP_LOOKUP_ELEM, array, &key, &got, 0);
    say("array lookup fresh %ld %llx", r, (unsigned long long)got);
    say("array update %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, ANY));
    r = elem(MAP_LOOKUP_ELEM, array, &key, &got, 0);
    say("array lookup %ld %llx", r, (unsigned long long)got);
    say("array noexist %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, NOEXIST));
    say("array exist %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, EXIST));
    say("array flags 3 %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, 3));
    say("array lock %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, ELEM_F_LOCK));
    say("array high flags %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, 1ULL << 40));
    key = 4;
    say("array past the end %ld", elem(MAP_UPDATE_ELEM, array, &key, &value, ANY));
    say("array lookup past the end %ld", elem(MAP_LOOKUP_ELEM, array, &key, &got, 0));
    say("array delete %ld", elem(MAP_DELETE_ELEM, array, &key, NULL, 0));
    say("array lookup and delete %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, array, &key, &got, 0));
    say("lookup flags %ld", elem(MAP_LOOKUP_ELEM, array, &key, &got, 1));
    say("lookup no key %ld", elem(MAP_LOOKUP_ELEM, array, NULL, &got, 0));
    key = 1;
    say("lookup no value %ld", elem(MAP_LOOKUP_ELEM, array, &key, NULL, 0));
    say("delete with a value %ld", elem(MAP_DELETE_ELEM, array, &key, &got, 0));
    uint32_t next = 99;
    r = elem(MAP_GET_NEXT_KEY, array, NULL, &next, 0);
    say("array first %ld %u", r, next);
    key = 2;
    r = elem(MAP_GET_NEXT_KEY, array, &key, &next, 0);
    say("array next %ld %u", r, next);
    key = 3;
    say("array last %ld", elem(MAP_GET_NEXT_KEY, array, &key, &next, 0));
    key = 77;
    r = elem(MAP_GET_NEXT_KEY, array, &key, &next, 0);
    say("array next of none %ld %u", r, next);
    int null = open("/dev/null", O_RDONLY);
    say("lookup of a file %ld", elem(MAP_LOOKUP_ELEM, null, &key, &got, 0));
    say("lookup of no fd %ld", elem(MAP_LOOKUP_ELEM, 999, &key, &got, 0));
    close(null);

    /* Access through the descriptor, and freezing. */
    int readonly = make(TYPE_ARRAY, 4, 8, 4, F_RDONLY);
    int writeonly = make(TYPE_ARRAY, 4, 8, 4, F_WRONLY);
    key = 0;
    say("read only update %ld lookup %ld", elem(MAP_UPDATE_ELEM, readonly, &key, &value, 0),
        elem(MAP_LOOKUP_ELEM, readonly, &key, &got, 0));
    say("write only lookup %ld next %ld update %ld", elem(MAP_LOOKUP_ELEM, writeonly, &key, &got, 0),
        elem(MAP_GET_NEXT_KEY, writeonly, NULL, &next, 0), elem(MAP_UPDATE_ELEM, writeonly, &key, &value, 0));
    say("freeze read only %ld", elem(MAP_FREEZE, readonly, NULL, NULL, 0));
    say("freeze %ld", elem(MAP_FREEZE, array, NULL, NULL, 0));
    say("freeze again %ld", elem(MAP_FREEZE, array, NULL, NULL, 0));
    key = 1;
    r = elem(MAP_LOOKUP_ELEM, array, &key, &got, 0);
    say("frozen update %ld lookup %ld %llx", elem(MAP_UPDATE_ELEM, array, &key, &value, 0), r,
        (unsigned long long)got);
    say("freeze with a key %ld", elem(MAP_FREEZE, writeonly, &key, NULL, 0));
    close(readonly);
    close(writeonly);
    close(array);

    /* A hash. */
    int hash = make(TYPE_HASH, 4, 8, 3, 0);
    key = 10;
    say("hash lookup none %ld", elem(MAP_LOOKUP_ELEM, hash, &key, &got, 0));
    say("hash exist none %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, EXIST));
    say("hash noexist %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, NOEXIST));
    say("hash noexist again %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, NOEXIST));
    value = 20;
    say("hash exist %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, EXIST));
    r = elem(MAP_LOOKUP_ELEM, hash, &key, &got, 0);
    say("hash lookup %ld %llu", r, (unsigned long long)got);
    say("hash flags 3 %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, 3));
    for (key = 11; key <= 12; key++) elem(MAP_UPDATE_ELEM, hash, &key, &value, ANY);
    key = 13;
    say("hash full %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, ANY));
    key = 12;
    say("hash full replace %ld", elem(MAP_UPDATE_ELEM, hash, &key, &value, ANY));
    keys("hash", hash);
    key = 99;
    r = elem(MAP_GET_NEXT_KEY, hash, &key, &next, 0);
    say("hash next of none %ld first %d", r, next >= 10 && next <= 12);
    key = 11;
    say("hash delete %ld", elem(MAP_DELETE_ELEM, hash, &key, NULL, 0));
    say("hash delete again %ld", elem(MAP_DELETE_ELEM, hash, &key, NULL, 0));
    key = 12;
    got = 0;
    r = elem(MAP_LOOKUP_AND_DELETE_ELEM, hash, &key, &got, 0);
    say("hash lookup and delete %ld %llu", r, (unsigned long long)got);
    say("hash lookup and delete again %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, hash, &key, &got, 0));
    say("hash lookup and delete flags %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, hash, &key, &got, 1));
    keys("hash after", hash);
    close(hash);
    return 0;
}

static long batch(int cmd, int fd, void *in, void *out, void *k, void *v, uint32_t *count, uint64_t flags) {
    union attr a;
    memset(&a, 0, sizeof a);
    a.batch.in_batch = (uintptr_t)in;
    a.batch.out_batch = (uintptr_t)out;
    a.batch.keys = (uintptr_t)k;
    a.batch.values = (uintptr_t)v;
    a.batch.count = *count;
    a.batch.map_fd = (uint32_t)fd;
    a.batch.flags = flags;
    long r = bpf(cmd, &a, sizeof a);
    *count = a.batch.count;
    return r;
}

static int case_batch(void) {
    int array = make(TYPE_ARRAY, 4, 8, 5, 0);
    uint32_t k[8] = {0, 1, 2, 3, 4, 5, 6, 7}, count = 3, out = 99;
    uint64_t v[8] = {100, 101, 102, 103, 104, 105, 106, 107};
    long r = batch(MAP_UPDATE_BATCH, array, NULL, NULL, k, v, &count, 0);
    say("array update batch %ld count %u", r, count);
    count = 8;
    r = batch(MAP_UPDATE_BATCH, array, NULL, NULL, k, v, &count, 0);
    say("array update batch past the end %ld count %u", r, count);
    count = 0;
    say("array update batch of none %ld", batch(MAP_UPDATE_BATCH, array, NULL, NULL, k, v, &count, 0));
    uint32_t gk[8];
    uint64_t gv[8];
    memset(gk, 0xff, sizeof gk);
    count = 3;
    r = batch(MAP_LOOKUP_BATCH, array, NULL, &out, gk, gv, &count, 0);
    say("array lookup batch %ld count %u out %u keys %u %u %u values %llu %llu %llu", r, count, out, gk[0], gk[1], gk[2],
        (unsigned long long)gv[0], (unsigned long long)gv[1], (unsigned long long)gv[2]);
    uint32_t in = out;
    count = 3;
    r = batch(MAP_LOOKUP_BATCH, array, &in, &out, gk, gv, &count, 0);
    say("array lookup batch on %ld count %u out %u keys %u %u", r, count, out, gk[0], gk[1]);
    count = 3;
    say("array delete batch %ld", batch(MAP_DELETE_BATCH, array, NULL, NULL, k, v, &count, 0));
    count = 3;
    say("array lookup and delete batch %ld", batch(MAP_LOOKUP_AND_DELETE_BATCH, array, NULL, &out, gk, gv, &count, 0));
    count = 1;
    say("batch flags %ld", batch(MAP_LOOKUP_BATCH, array, NULL, &out, gk, gv, &count, 1));
    close(array);

    int hash = make(TYPE_HASH, 4, 8, 8, 0);
    count = 5;
    r = batch(MAP_UPDATE_BATCH, hash, NULL, NULL, k, v, &count, 0);
    say("hash update batch %ld count %u", r, count);
    keys("hash", hash);
    /* Addresses at the top of the address space wrap, and fault. */
    count = 2;
    r = batch(MAP_UPDATE_BATCH, hash, NULL, NULL, (void *)~(uintptr_t)3, v, &count, 0);
    say("hash update batch from the top %ld count %u", r, count);
    count = 8;
    memset(gk, 0, sizeof gk);
    r = batch(MAP_LOOKUP_BATCH, hash, NULL, &out, gk, gv, &count, 0);
    qsort(gk, count, sizeof gk[0], compare);
    say("hash lookup batch %ld count %u keys %u %u %u %u %u", r, count, gk[0], gk[1], gk[2], gk[3], gk[4]);
    count = 1;
    say("hash lookup batch flags %ld", batch(MAP_LOOKUP_BATCH, hash, NULL, &out, gk, gv, &count, 1));
    in = 1u << 20;
    count = 8;
    say("hash lookup batch past the buckets %ld", batch(MAP_LOOKUP_BATCH, hash, &in, &out, gk, gv, &count, 0));
    uint32_t gone[2] = {1, 3};
    count = 2;
    r = batch(MAP_DELETE_BATCH, hash, NULL, NULL, gone, NULL, &count, 0);
    say("hash delete batch %ld count %u", r, count);
    count = 2;
    r = batch(MAP_DELETE_BATCH, hash, NULL, NULL, gone, NULL, &count, 0);
    say("hash delete batch again %ld count %u", r, count);
    keys("hash after delete", hash);
    count = 8;
    r = batch(MAP_LOOKUP_AND_DELETE_BATCH, hash, NULL, &out, gk, gv, &count, 0);
    say("hash lookup and delete batch %ld count %u", r, count);
    keys("hash emptied", hash);
    close(hash);

    /* Without CAP_BPF, no map is made. */
    pid_t child = fork();
    if (child == 0) {
        if (setresuid(65534, 65534, 65534) < 0) _exit(1);
        union attr a = map_attr(TYPE_ARRAY, 4, 8, 4, 0);
        say("unprivileged array %ld", bpf(MAP_CREATE, &a, sizeof a));
        a = map_attr(TYPE_HASH, 4, 8, 4, F_ZERO_SEED);
        say("unprivileged zero seed %ld", bpf(MAP_CREATE, &a, sizeof a));
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    say("child status %d", status);
    return 0;
}

/* The ID BPF_OBJ_GET_INFO_BY_FD gives a map. */
static uint32_t id_of(int fd) {
    struct map_info mi;
    memset(&mi, 0, sizeof mi);
    union attr q;
    memset(&q, 0, sizeof q);
    q.info.bpf_fd = (uint32_t)fd;
    q.info.info_len = sizeof mi;
    q.info.info = (uintptr_t)&mi;
    return bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q) < 0 ? 0 : mi.id;
}

static long next_id(uint32_t start, uint32_t *next) {
    union attr a;
    memset(&a, 0, sizeof a);
    a.id.start_id = start;
    a.id.next_id = 12345;
    long r = bpf(MAP_GET_NEXT_ID, &a, sizeof a);
    *next = a.id.next_id;
    return r;
}

static long fd_by_id(uint32_t id, uint32_t open_flags) {
    union attr a;
    memset(&a, 0, sizeof a);
    a.id.start_id = id;
    a.id.open_flags = open_flags;
    return bpf(MAP_GET_FD_BY_ID, &a, sizeof a);
}

/* Whether an ID is among those BPF_MAP_GET_NEXT_ID walks from 0, and how
   the walk ends. */
static int listed(uint32_t id, long *end) {
    uint32_t at = 0, next;
    int found = 0;
    while ((*end = next_id(at, &next)) == 0) {
        if (next == id) found = 1;
        if (next <= at) break;
        at = next;
    }
    return found;
}

static int case_ids(void) {
    int map = make(TYPE_ARRAY, 4, 8, 4, 0);
    int other = make(TYPE_HASH, 4, 8, 4, 0);
    uint32_t id = id_of(map), second = id_of(other), next = 0;
    say("ids %d increasing %d", id > 0, second > id);
    long r = next_id(id - 1, &next);
    say("next of the one before %ld is it %d", r, next == id);
    r = next_id(id, &next);
    say("next %ld past it %d", r, next > id);
    long end;
    int found = listed(id, &end);
    say("listed %d end %ld", found, end);
    say("next from the last %ld", next_id(0x7ffffffe, &next));
    say("next from int max %ld", next_id(0x7fffffff, &next));
    union attr a;
    memset(&a, 0, sizeof a);
    a.bytes[8] = 1;
    say("next with more %ld", bpf(MAP_GET_NEXT_ID, &a, sizeof a));

    long fd = fd_by_id(id, 0);
    say("fd by id %s same %d cloexec %d access %d", fd >= 0 ? "fd" : "error", fd >= 0 && id_of((int)fd) == id,
        fd >= 0 && (fcntl((int)fd, F_GETFD) & FD_CLOEXEC) != 0, fd >= 0 ? fcntl((int)fd, F_GETFL) & O_ACCMODE : -1);
    uint32_t key = 2;
    uint64_t value = 77, got = 0;
    elem(MAP_UPDATE_ELEM, map, &key, &value, ANY);
    r = elem(MAP_LOOKUP_ELEM, (int)fd, &key, &got, 0);
    say("seen through it %ld %llu", r, (unsigned long long)got);
    long readonly = fd_by_id(id, F_RDONLY), writeonly = fd_by_id(id, F_WRONLY);
    say("read only access %d update %ld write only access %d lookup %ld",
        readonly >= 0 ? fcntl((int)readonly, F_GETFL) & O_ACCMODE : (int)readonly,
        elem(MAP_UPDATE_ELEM, (int)readonly, &key, &value, ANY),
        writeonly >= 0 ? fcntl((int)writeonly, F_GETFL) & O_ACCMODE : (int)writeonly,
        elem(MAP_LOOKUP_ELEM, (int)writeonly, &key, &got, 0));
    close((int)readonly);
    close((int)writeonly);
    say("both access %ld", fd_by_id(id, F_RDONLY | F_WRONLY));
    say("other flag %ld", fd_by_id(id, 1));
    memset(&a, 0, sizeof a);
    a.id.start_id = id;
    a.bytes[12] = 1;
    say("fd by id with more %ld", bpf(MAP_GET_FD_BY_ID, &a, sizeof a));
    say("fd by id 0 %ld", fd_by_id(0, 0));

    /* A map stays while a descriptor has it, and its ID goes with it. */
    close(map);
    r = elem(MAP_LOOKUP_ELEM, (int)fd, &key, &got, 0);
    long again = fd_by_id(id, 0);
    say("after its first closes %ld %llu again %s", r, (unsigned long long)got, again >= 0 ? "fd" : "error");
    close((int)again);
    close((int)fd);
    say("after all close %ld", fd_by_id(id, 0));
    r = next_id(id - 1, &next);
    say("next of the one before %d", r == -ENOENT || next != id);
    found = listed(id, &end);
    say("listed after %d end %ld", found, end);

    /* Without CAP_SYS_ADMIN, the IDs are not given; the attributes are
       checked first. */
    pid_t child = fork();
    if (child == 0) {
        if (setresuid(65534, 65534, 65534) < 0) _exit(1);
        say("unprivileged next %ld", next_id(0, &next));
        say("unprivileged fd by id %ld", fd_by_id(second, 0));
        say("unprivileged next from int max %ld", next_id(0x7fffffff, &next));
        say("unprivileged other flag %ld", fd_by_id(second, 1));
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    say("child status %d", status);
    close(other);
    return 0;
}

/* The memlock line of a map's fdinfo. */
static unsigned long long memlock(int fd) {
    char path[64], line[128];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    FILE *info = fopen(path, "r");
    unsigned long long value = 0;
    while (info && fgets(line, sizeof line, info))
        if (sscanf(line, "memlock: %llu", &value) == 1) break;
    if (info) fclose(info);
    return value;
}

static void array_memory(uint32_t value, uint32_t entries, uint32_t flags) {
    int fd = make(TYPE_ARRAY, 4, value, entries, flags);
    say("array value %u entries %u flags %#x memlock %llu", value, entries, flags, memlock(fd));
    close(fd);
}

static int case_memory(void) {
    array_memory(8, 1, 0);
    array_memory(8, 1000, 0);
    array_memory(1, 3, 0);
    array_memory(24, 10, F_MMAPABLE);
    array_memory(4097, 3, F_MMAPABLE);

    /* A hash made as it is filled, by the elements it holds. */
    int hash = make(TYPE_HASH, 4, 8, 4, F_NO_PREALLOC);
    say("sparse hash empty %llu", memlock(hash));
    uint64_t value = 1;
    for (uint32_t key = 0; key < 3; key++) elem(MAP_UPDATE_ELEM, hash, &key, &value, ANY);
    say("sparse hash of 3 %llu", memlock(hash));
    uint32_t key = 1;
    elem(MAP_DELETE_ELEM, hash, &key, NULL, 0);
    say("sparse hash of 2 %llu", memlock(hash));
    close(hash);
    hash = make(TYPE_HASH, 9, 3, 100, F_NO_PREALLOC);
    say("sparse hash key 9 value 3 %llu", memlock(hash));
    close(hash);

    /* A preallocated one, which counts a spare element a CPU: how sizes
       differ, and that what it holds does not change it. */
    int one = make(TYPE_HASH, 4, 8, 1, 0), hundred = make(TYPE_HASH, 4, 8, 100, 0);
    unsigned long long before = memlock(hundred);
    say("hash of 100 less hash of 1 %llu", before - memlock(one));
    key = 5;
    elem(MAP_UPDATE_ELEM, hundred, &key, &value, ANY);
    say("hash filled same %d", memlock(hundred) == before);
    close(one);
    close(hundred);

    /* More than any machine has. */
    create("huge array", map_attr(TYPE_ARRAY, 4, 1 << 30, 1 << 20, 0));
    create("huge mmapable array", map_attr(TYPE_ARRAY, 4, 1 << 30, 1 << 20, F_MMAPABLE));
    create("huge hash", map_attr(TYPE_HASH, 4, 1 << 21, 1 << 20, 0));
    union attr a = map_attr(TYPE_HASH, 4, 1 << 21, 1 << 20, F_NO_PREALLOC);
    long fd = bpf(MAP_CREATE, &a, sizeof a);
    say("huge sparse hash %s memlock %llu", fd >= 0 ? "fd" : "error", fd >= 0 ? memlock((int)fd) : 0);
    if (fd >= 0) close((int)fd);
    create("hash past the buckets", map_attr(TYPE_HASH, 4, 8, (1u << 27) + 1, F_NO_PREALLOC));
    create("hash past 2^31", map_attr(TYPE_HASH, 4, 8, (1u << 31) + 1, F_NO_PREALLOC));
    return 0;
}


int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "bpf-calls")) return case_calls();
    if (!strcmp(mode, "bpf-elements")) return case_elements();
    if (!strcmp(mode, "bpf-batch")) return case_batch();
    if (!strcmp(mode, "bpf-ids")) return case_ids();
    if (!strcmp(mode, "bpf-memory")) return case_memory();
    return 2;
}
