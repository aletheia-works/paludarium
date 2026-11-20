/* bpf, compared with Linux, for its maps: the checks of every command,
   BPF_MAP_CREATE of arrays and hashes with its errors, the elements
   (lookup, update, delete, next key, lookup and delete), freezing, the
   batch commands, BPF_OBJ_GET_INFO_BY_FD, fdinfo, and the rule that keeps
   a user without CAP_BPF out (kernel.unprivileged_bpf_disabled, 2).
   bpf-lru: LRU hashes, which give up a key when they are full; the case
   runs on one CPU, as the emulator does, since each CPU has its own free
   and pending lists, which decide which key goes.
   bpf-queue: queues and stacks, which push, peek and pop values without
   keys.
   bpf-bloom: bloom filters, with BPF_F_ZERO_SEED, so that which values
   seem to be there, false positives included, is the same as on Linux;
   with a random seed, only that what was pushed is there.
   bpf-lpm: longest-prefix-match tries, of IPv4 prefixes and of longer
   keys: which prefix holds an address, the order of the next keys (more
   specific prefixes first), the bytes past a prefix that an element
   keeps, the room they take, and the batch commands.
   bpf-maps: arrays and hashes of maps, which hold other maps by their
   descriptors: the template the inner map's descriptor gives at creation,
   which maps fit it, the IDs a lookup gives, an inner map kept after its
   descriptor closes and given up on delete, the flags, the batch
   commands and the room they take.

   The map IDs (BPF_MAP_GET_NEXT_ID, BPF_MAP_GET_FD_BY_ID) are compared by
   what they find, and the memory fdinfo gives a map (memlock), with the
   ENOMEM of a map larger than any machine, as the CI machines' kernel
   (Ubuntu's Linux 7.0) counts it.

   A hash's keys come in an order of its buckets, which a random seed
   picks: they are given sorted. The IDs themselves, which other maps on
   the machine move, the memory of a preallocated hash, which counts the
   possible CPUs, but for its difference between sizes, and the size Linux
   knows of its union are not printed. Programs, BTF and links are not
   used, but for BPF_PROG_LOAD's checks of its arguments. The cases run as
   root, as the guest does. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
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
#define COMMON_ATTRS (1 << 16)

#define TYPE_HASH 1
#define TYPE_ARRAY 2
#define TYPE_LRU_HASH 9
#define TYPE_ARRAY_OF_MAPS 12
#define TYPE_HASH_OF_MAPS 13
#define TYPE_LPM_TRIE 11
#define TYPE_QUEUE 22
#define TYPE_STACK 23
#define TYPE_BLOOM_FILTER 30

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
#define F_INNER_MAP (1 << 12)

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

static long bpf_common(int cmd, void *attr, unsigned size, void *common, unsigned common_size) {
    long result = syscall(SYS_bpf, cmd, attr, size, common, common_size);
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

    /* Master's BPF_COMMON_ATTRS (1 << 16): a struct bpf_common_attr
       (log_buf, log_size, log_level, log_true_size) in the fourth and
       fifth arguments. Linux 7.0 has no such flag, so the command is a
       number with no command, after the size and the copy. */
    uint64_t common[3] = {0, 0, 0};
    say("common attrs none %ld", bpf_common(MAP_CREATE | COMMON_ATTRS, &a, sizeof a, NULL, 0));
    say("common attrs given %ld",
        bpf_common(MAP_CREATE | COMMON_ATTRS, &a, sizeof a, common, sizeof common));
    say("common attrs fault %ld",
        bpf_common(MAP_CREATE | COMMON_ATTRS, NULL, sizeof a, common, sizeof common));
    say("common attrs past a page %ld", bpf_common(MAP_CREATE | COMMON_ATTRS, &a, 4097, NULL, 0));
    say("common attrs get next id %ld",
        bpf_common(MAP_GET_NEXT_ID | COMMON_ATTRS, &a, sizeof a, NULL, 0));

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


/* Updates key with value, and says what that gave. */
static void put(const char *name, int fd, uint32_t key, uint64_t value, uint64_t flags) {
    say("%s %u: %ld", name, key, elem(MAP_UPDATE_ELEM, fd, &key, &value, flags));
}

static int case_lru(void) {
    /* One CPU, so that every command uses the same lists. */
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(sched_getcpu(), &one);
    if (sched_setaffinity(0, sizeof one, &one) < 0) return 1;

    create("lru no prealloc", map_attr(TYPE_LRU_HASH, 4, 8, 4, F_NO_PREALLOC));
    create("lru no common lru numa", map_attr(TYPE_LRU_HASH, 4, 8, 4, F_NO_COMMON_LRU | F_NUMA_NODE));
    create("lru numa", map_attr(TYPE_LRU_HASH, 4, 8, 4, F_NUMA_NODE));
    create("lru key 0", map_attr(TYPE_LRU_HASH, 0, 8, 4, 0));
    create("lru entries 0", map_attr(TYPE_LRU_HASH, 4, 8, 0, 0));
    create("lru mmapable", map_attr(TYPE_LRU_HASH, 4, 8, 4, F_MMAPABLE));
    create("lru zero seed", map_attr(TYPE_LRU_HASH, 4, 8, 4, F_ZERO_SEED));
    create("lru too big", map_attr(TYPE_LRU_HASH, 4, 1 << 22, 4, 0));
    create("lru no common lru", map_attr(TYPE_LRU_HASH, 4, 8, 4, F_NO_COMMON_LRU));

    /* Four entries: a CPU takes one free element at a time, on any machine
       of two CPUs or more. */
    int lru = make(TYPE_LRU_HASH, 4, 8, 4, 0);
    say("lru memlock %llu", memlock(lru));
    for (uint32_t key = 1; key <= 5; key++) put("add", lru, key, key, ANY);
    keys("lru full", lru);
    put("replace", lru, 2, 20, ANY);
    keys("lru replaced", lru);
    put("add", lru, 6, 6, ANY);
    keys("lru added", lru);
    put("refused", lru, 6, 60, NOEXIST);
    keys("lru refused", lru);
    put("missing", lru, 9, 9, EXIST);
    keys("lru missing", lru);
    uint32_t key = 6;
    uint64_t value = 0;
    long r = elem(MAP_LOOKUP_ELEM, lru, &key, &value, 0);
    say("lookup 6 %ld value %llu", r, (unsigned long long)value);
    key = 5;
    say("delete 5 %ld", elem(MAP_DELETE_ELEM, lru, &key, NULL, 0));
    say("delete 5 again %ld", elem(MAP_DELETE_ELEM, lru, &key, NULL, 0));
    keys("lru deleted", lru);
    for (key = 7; key <= 9; key++) put("add", lru, key, key, ANY);
    keys("lru refilled", lru);
    key = 8;
    value = 0;
    r = elem(MAP_LOOKUP_AND_DELETE_ELEM, lru, &key, &value, 0);
    say("lookup and delete 8 %ld value %llu", r, (unsigned long long)value);
    keys("lru after lookup and delete", lru);
    /* Replaced keys are referenced, and outlast the others. */
    for (key = 10; key <= 30; key++) {
        put("add", lru, key, key, ANY);
        if (key % 3 == 0) put("replace", lru, key, key + 100, ANY);
    }
    keys("lru after many", lru);
    uint32_t k[8] = {40, 41, 42, 43, 44, 45, 46, 47}, count = 6, gk[8];
    uint64_t v[8] = {0}, gv[8];
    r = batch(MAP_UPDATE_BATCH, lru, NULL, NULL, k, v, &count, 0);
    say("update batch %ld count %u", r, count);
    keys("lru after batch", lru);
    count = 8;
    uint32_t out = 0;
    r = batch(MAP_LOOKUP_AND_DELETE_BATCH, lru, NULL, &out, gk, gv, &count, 0);
    qsort(gk, count, sizeof gk[0], compare);
    printf("lookup and delete batch %ld count %u keys", r, count);
    for (uint32_t i = 0; i < count; i++) printf(" %u", gk[i]);
    putchar('\n');
    keys("lru emptied", lru);
    say("lru memlock after %llu", memlock(lru));
    close(lru);

    /* Lists for each CPU: one entry is one for each, so this CPU holds just
       one key. */
    lru = make(TYPE_LRU_HASH, 4, 8, 1, F_NO_COMMON_LRU);
    for (key = 1; key <= 3; key++) put("own add", lru, key, key, ANY);
    keys("own lists", lru);
    close(lru);
    return 0;
}

/* Pops (or with peek, looks at) a queue's or stack's values until there
   are none. */
static void drain(const char *name, int fd) {
    printf("%s", name);
    for (;;) {
        uint64_t value = 0;
        long r = elem(MAP_LOOKUP_AND_DELETE_ELEM, fd, NULL, &value, 0);
        if (r < 0) {
            printf(" end %ld\n", r);
            break;
        }
        printf(" %llu", (unsigned long long)value);
    }
    fflush(stdout);
}

static int case_queue(void) {
    create("queue key 4", map_attr(TYPE_QUEUE, 4, 8, 4, 0));
    create("queue value 0", map_attr(TYPE_QUEUE, 0, 0, 4, 0));
    create("queue entries 0", map_attr(TYPE_QUEUE, 0, 8, 0, 0));
    create("queue no prealloc", map_attr(TYPE_QUEUE, 0, 8, 4, F_NO_PREALLOC));
    create("queue zero seed", map_attr(TYPE_QUEUE, 0, 8, 4, F_ZERO_SEED));
    create("queue mmapable", map_attr(TYPE_QUEUE, 0, 8, 4, F_MMAPABLE));
    create("queue numa", map_attr(TYPE_QUEUE, 0, 8, 4, F_NUMA_NODE));
    create("queue value too big", map_attr(TYPE_QUEUE, 0, (1 << 22) + 1, 4, 0));
    create("stack key 4", map_attr(TYPE_STACK, 4, 8, 4, 0));
    const uint32_t types[2] = {TYPE_QUEUE, TYPE_STACK};
    const char *names[2] = {"queue", "stack"};
    for (int t = 0; t < 2; t++) {
        const char *name = names[t];
        int fd = make(types[t], 0, 8, 3, 0);
        say("%s memlock %llu", name, memlock(fd));
        uint64_t value = 0;
        uint32_t key = 0;
        say("%s peek empty %ld", name, elem(MAP_LOOKUP_ELEM, fd, NULL, &value, 0));
        for (uint64_t v = 1; v <= 3; v++) say("%s push %llu %ld", name, (unsigned long long)v, elem(MAP_UPDATE_ELEM, fd, NULL, &v, ANY));
        value = 4;
        say("%s push full %ld", name, elem(MAP_UPDATE_ELEM, fd, NULL, &value, ANY));
        say("%s push noexist %ld", name, elem(MAP_UPDATE_ELEM, fd, NULL, &value, NOEXIST));
        say("%s push lock %ld", name, elem(MAP_UPDATE_ELEM, fd, NULL, &value, ELEM_F_LOCK));
        say("%s push with a key %ld", name, elem(MAP_UPDATE_ELEM, fd, &key, &value, ANY));
        say("%s push exist %ld", name, elem(MAP_UPDATE_ELEM, fd, NULL, &value, EXIST));
        value = 0;
        long r = elem(MAP_LOOKUP_ELEM, fd, NULL, &value, 0);
        say("%s peek %ld value %llu", name, r, (unsigned long long)value);
        say("%s peek with a key %ld", name, elem(MAP_LOOKUP_ELEM, fd, &key, &value, 0));
        say("%s peek to nowhere %ld", name, elem(MAP_LOOKUP_ELEM, fd, NULL, (void *)8, 0));
        say("%s delete %ld", name, elem(MAP_DELETE_ELEM, fd, NULL, NULL, 0));
        say("%s delete with a key %ld", name, elem(MAP_DELETE_ELEM, fd, &key, NULL, 0));
        uint32_t next;
        say("%s next key %ld", name, elem(MAP_GET_NEXT_KEY, fd, NULL, &next, 0));
        say("%s next key of a key %ld", name, elem(MAP_GET_NEXT_KEY, fd, &key, &next, 0));
        say("%s pop lock %ld", name, elem(MAP_LOOKUP_AND_DELETE_ELEM, fd, NULL, &value, ELEM_F_LOCK));
        uint64_t values[4];
        uint32_t keys[4], count = 2, out;
        say("%s lookup batch %ld", name, batch(MAP_LOOKUP_BATCH, fd, NULL, &out, keys, values, &count, 0));
        count = 2;
        say("%s update batch %ld", name, batch(MAP_UPDATE_BATCH, fd, NULL, NULL, keys, values, &count, 0));
        drain(name, fd);
        value = 9;
        elem(MAP_UPDATE_ELEM, fd, NULL, &value, ANY);
        say("%s pop to nowhere %ld", name, elem(MAP_LOOKUP_AND_DELETE_ELEM, fd, NULL, (void *)8, 0));
        drain(name, fd);

        /* Read only, and frozen. */
        int readonly = make(types[t], 0, 8, 3, F_RDONLY);
        say("%s read only push %ld pop %ld", name, elem(MAP_UPDATE_ELEM, readonly, NULL, &value, ANY),
            elem(MAP_LOOKUP_AND_DELETE_ELEM, readonly, NULL, &value, 0));
        close(readonly);
        union attr f;
        memset(&f, 0, sizeof f);
        f.elem.map_fd = (uint32_t)fd;
        say("%s freeze %ld", name, bpf(MAP_FREEZE, &f, sizeof f));
        say("%s frozen push %ld peek %ld", name, elem(MAP_UPDATE_ELEM, fd, NULL, &value, ANY),
            elem(MAP_LOOKUP_ELEM, fd, NULL, &value, 0));
        close(fd);
    }
    return 0;
}

/* bpf-prog-load: BPF_PROG_LOAD's checks of its arguments, each case wrong
   in one way only, so that Linux and the emulator stop at the same check.
   Only the errors are compared; the programs the verifier takes and
   refuses are bpf-prog's. */
#define PROG_LOAD 5
#define PROG_SOCKET_FILTER 1
#define PROG_TOKEN_FD (1 << 16)

/* union bpf_attr for BPF_PROG_LOAD, to keyring_id, the last field. */
struct prog_attr {
    uint32_t prog_type, insn_cnt;
    uint64_t insns, license;
    uint32_t log_level, log_size;
    uint64_t log_buf;
    uint32_t kern_version, prog_flags;
    char prog_name[16];
    uint32_t prog_ifindex, expected_attach_type, prog_btf_fd, func_info_rec_size;
    uint64_t func_info;
    uint32_t func_info_cnt, line_info_rec_size;
    uint64_t line_info;
    uint32_t line_info_cnt, attach_btf_id, attach_prog_fd, core_relo_cnt;
    uint64_t fd_array, core_relos;
    uint32_t core_relo_rec_size, log_true_size;
    int32_t prog_token_fd;
    uint32_t fd_array_cnt;
    uint64_t signature;
    uint32_t signature_size;
    int32_t keyring_id;
};
_Static_assert(sizeof(struct prog_attr) == 168, "union bpf_attr's size");

/* r0 = 0; exit */
static const uint64_t prog_insns[2] = { 0x00000000000000b7ULL, 0x0000000000000095ULL };
static char prog_log[4096];

static struct prog_attr prog(void) {
    struct prog_attr p;
    memset(&p, 0, sizeof p);
    p.prog_type = PROG_SOCKET_FILTER;
    p.insn_cnt = 2;
    p.insns = (uintptr_t)prog_insns;
    p.license = (uintptr_t)"GPL";
    return p;
}

static void load(const char *name, struct prog_attr p) {
    say("%s %ld", name, bpf(PROG_LOAD, &p, sizeof p));
}

static int case_prog_load(void) {
    int null = open("/dev/null", O_RDONLY);
    struct prog_attr p = prog();
    p.prog_flags = 1 << 8;
    load("unknown flag", p);
    p = prog();
    p.prog_flags = PROG_TOKEN_FD;
    p.prog_token_fd = 1000;
    load("token flag without a descriptor", p);
    p.prog_token_fd = null;
    load("token flag with another file", p);
    p = prog();
    p.insn_cnt = 0;
    load("no instructions", p);
    p.insn_cnt = 1000001;
    load("more than the complexity limit", p);
    p = prog();
    p.attach_prog_fd = null;
    load("attach to another file", p);
    p = prog();
    p.attach_btf_id = 1;
    load("attach BTF ID", p);
    p = prog();
    p.insns = 8;
    load("instructions at no memory", p);
    p = prog();
    p.license = 8;
    load("license at no memory", p);
    p = prog();
    p.prog_type = 1000;
    load("unknown type", p);
    p = prog();
    memcpy(p.prog_name, "bad-name", 9);
    load("name with a dash", p);
    p = prog();
    p.log_buf = (uintptr_t)prog_log;
    p.log_level = 1;
    load("log buffer without a size", p);
    close(null);

    /* Without CAP_BPF, kernel.unprivileged_bpf_disabled (2) keeps every
       load out, before its size is looked at. */
    pid_t child = fork();
    if (child == 0) {
        if (setresuid(65534, 65534, 65534) < 0) _exit(1);
        load("unprivileged socket filter", prog());
        struct prog_attr q = prog();
        q.insn_cnt = 0;
        load("unprivileged no instructions", q);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    say("child status %d", status);
    return 0;
}

static union attr bloom_attr(uint32_t value, uint32_t entries, uint32_t flags, uint64_t extra) {
    union attr a = map_attr(TYPE_BLOOM_FILTER, 0, value, entries, flags);
    a.map_extra = extra;
    return a;
}

/* Which of the values from..to (as 4-byte, or the first `size` bytes of
   12-byte, values) the filter says may be there, as a string of 0 and 1. */
static void seen(const char *name, int fd, uint32_t size, uint32_t from, uint32_t to) {
    printf("%s ", name);
    for (uint32_t v = from; v < to; v++) {
        unsigned char value[16] = {0};
        memcpy(value, &v, sizeof v);
        value[size - 1] ^= 0x5a;
        putchar(elem(MAP_LOOKUP_ELEM, fd, NULL, value, 0) == 0 ? '1' : '0');
    }
    putchar('\n');
    fflush(stdout);
}

static void fill(int fd, uint32_t size, uint32_t from, uint32_t to) {
    for (uint32_t v = from; v < to; v++) {
        unsigned char value[16] = {0};
        memcpy(value, &v, sizeof v);
        value[size - 1] ^= 0x5a;
        elem(MAP_UPDATE_ELEM, fd, NULL, value, ANY);
    }
}

static int case_bloom(void) {
    create("bloom key 4", map_attr(TYPE_BLOOM_FILTER, 4, 4, 10, 0));
    create("bloom value 0", bloom_attr(0, 10, 0, 0));
    create("bloom entries 0", bloom_attr(4, 0, 0, 0));
    create("bloom extra 16", bloom_attr(4, 10, 0, 16));
    create("bloom no prealloc", bloom_attr(4, 10, F_NO_PREALLOC, 0));
    create("bloom mmapable", bloom_attr(4, 10, F_MMAPABLE, 0));
    create("bloom numa", bloom_attr(4, 10, F_NUMA_NODE, 0));
    create("bloom value too big", bloom_attr((1 << 22) + 1, 10, 0, 0));
    create("bloom both prog access", bloom_attr(4, 10, F_RDONLY_PROG | F_WRONLY_PROG, 0));
    union attr h = map_attr(TYPE_HASH, 4, 4, 10, 0);
    h.map_extra = 1;
    create("hash with extra", h);

    const uint32_t sizes[][3] = {{4, 1, 0}, {4, 100, 0}, {4, 1000, 3}, {3, 50, 1}, {8, 5000, 15}};
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        union attr a = bloom_attr(sizes[i][0], sizes[i][1], F_ZERO_SEED, sizes[i][2]);
        int fd = (int)bpf(MAP_CREATE, &a, sizeof a);
        say("bloom value %u entries %u extra %u memlock %llu", sizes[i][0], sizes[i][1], sizes[i][2], memlock(fd));
        close(fd);
    }

    union attr a = bloom_attr(4, 20, F_ZERO_SEED, 0);
    int fd = (int)bpf(MAP_CREATE, &a, sizeof a);
    struct map_info mi;
    memset(&mi, 0, sizeof mi);
    union attr q;
    memset(&q, 0, sizeof q);
    q.info.bpf_fd = (uint32_t)fd;
    q.info.info_len = sizeof mi;
    q.info.info = (uintptr_t)&mi;
    long r = bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q);
    say("bloom info %ld type %u key %u value %u extra %llu", r, mi.type, mi.key_size, mi.value_size,
        (unsigned long long)mi.map_extra);
    char path[64], line[128];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    FILE *info = fopen(path, "r");
    while (info && fgets(line, sizeof line, info))
        if (!strncmp(line, "map_extra", 9)) fputs(line, stdout);
    if (info) fclose(info);
    fflush(stdout);

    uint32_t value = 7, key = 0, next;
    say("bloom peek empty %ld", elem(MAP_LOOKUP_ELEM, fd, NULL, &value, 0));
    say("bloom push %ld", elem(MAP_UPDATE_ELEM, fd, NULL, &value, ANY));
    say("bloom peek %ld", elem(MAP_LOOKUP_ELEM, fd, NULL, &value, 0));
    say("bloom push noexist %ld", elem(MAP_UPDATE_ELEM, fd, NULL, &value, NOEXIST));
    say("bloom push exist %ld", elem(MAP_UPDATE_ELEM, fd, NULL, &value, EXIST));
    say("bloom push lock %ld", elem(MAP_UPDATE_ELEM, fd, NULL, &value, ELEM_F_LOCK));
    say("bloom push with a key %ld", elem(MAP_UPDATE_ELEM, fd, &key, &value, ANY));
    say("bloom peek with a key %ld", elem(MAP_LOOKUP_ELEM, fd, &key, &value, 0));
    say("bloom peek from nowhere %ld", elem(MAP_LOOKUP_ELEM, fd, NULL, (void *)8, 0));
    say("bloom delete %ld", elem(MAP_DELETE_ELEM, fd, NULL, NULL, 0));
    say("bloom next key %ld", elem(MAP_GET_NEXT_KEY, fd, NULL, &next, 0));
    say("bloom lookup and delete %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, fd, NULL, &value, 0));
    uint32_t keys[2], count = 2, out;
    uint32_t values[2] = {1, 2};
    say("bloom update batch %ld", batch(MAP_UPDATE_BATCH, fd, NULL, NULL, keys, values, &count, 0));
    count = 2;
    say("bloom lookup batch %ld", batch(MAP_LOOKUP_BATCH, fd, NULL, &out, keys, values, &count, 0));
    close(fd);

    /* What seems to be there, false positives and all, of filters that
       hash words (jhash2) and bytes (jhash), with 5, 1 and 15 hashes. */
    const uint32_t kinds[][4] = {{4, 20, 0, 0}, {4, 20, 1, 0}, {4, 64, 15, 0}, {3, 20, 0, 0}, {13, 30, 2, 0}};
    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        a = bloom_attr(kinds[i][0] <= 4 ? kinds[i][0] : 13, kinds[i][1], F_ZERO_SEED, kinds[i][2]);
        fd = (int)bpf(MAP_CREATE, &a, sizeof a);
        uint32_t size = kinds[i][0];
        fill(fd, size, 0, kinds[i][1]);
        char name[64];
        snprintf(name, sizeof name, "bloom value %u extra %u seen", size, kinds[i][2]);
        seen(name, fd, size, 0, 200);
        close(fd);
    }

    /* A random seed: what was pushed is there. */
    a = bloom_attr(4, 100, 0, 0);
    fd = (int)bpf(MAP_CREATE, &a, sizeof a);
    fill(fd, 4, 0, 100);
    int all = 1;
    for (uint32_t v = 0; v < 100; v++) {
        unsigned char b[4];
        memcpy(b, &v, 4);
        b[3] ^= 0x5a;
        all &= elem(MAP_LOOKUP_ELEM, fd, NULL, b, 0) == 0;
    }
    say("bloom random seed all there %d", all);
    close(fd);
    return 0;
}

/* An IPv4 trie's key: a prefix length and an address. */
struct v4 {
    uint32_t length;
    unsigned char address[4];
};

static struct v4 v4(unsigned a, unsigned b, unsigned c, unsigned d, uint32_t length) {
    struct v4 key = {length, {(unsigned char)a, (unsigned char)b, (unsigned char)c, (unsigned char)d}};
    return key;
}

/* Which value the trie gives an address, or the error. */
static void holds(int fd, unsigned a, unsigned b, unsigned c, unsigned d, uint32_t length) {
    struct v4 key = v4(a, b, c, d, length);
    uint32_t value = 0;
    long r = elem(MAP_LOOKUP_ELEM, fd, &key, &value, 0);
    if (r == 0)
        say("lpm %u.%u.%u.%u/%u holds %u", a, b, c, d, length, value);
    else
        say("lpm %u.%u.%u.%u/%u %ld", a, b, c, d, length, r);
}

static long lpm_put(int fd, unsigned a, unsigned b, unsigned c, unsigned d, uint32_t length, uint32_t value,
                uint64_t flags) {
    struct v4 key = v4(a, b, c, d, length);
    return elem(MAP_UPDATE_ELEM, fd, &key, &value, flags);
}

static long lpm_take(int fd, unsigned a, unsigned b, unsigned c, unsigned d, uint32_t length) {
    struct v4 key = v4(a, b, c, d, length);
    return elem(MAP_DELETE_ELEM, fd, &key, NULL, 0);
}

/* The trie's keys in the order MAP_GET_NEXT_KEY gives them. */
static void order(const char *name, int fd) {
    struct v4 key, next;
    long r = elem(MAP_GET_NEXT_KEY, fd, NULL, &next, 0);
    printf("%s", name);
    for (int n = 0; r == 0 && n < 32; n++) {
        printf(" %u.%u.%u.%u/%u", next.address[0], next.address[1], next.address[2], next.address[3],
               next.length);
        key = next;
        r = elem(MAP_GET_NEXT_KEY, fd, &key, &next, 0);
    }
    printf(" end %ld\n", r);
    fflush(stdout);
}

static union attr lpm_attr(uint32_t key, uint32_t value, uint32_t entries, uint32_t flags) {
    return map_attr(TYPE_LPM_TRIE, key, value, entries, flags);
}

static int case_lpm(void) {
    create("lpm key 4", lpm_attr(4, 4, 10, F_NO_PREALLOC));
    create("lpm key 5", lpm_attr(5, 4, 10, F_NO_PREALLOC));
    create("lpm key 260", lpm_attr(260, 4, 10, F_NO_PREALLOC));
    create("lpm key 261", lpm_attr(261, 4, 10, F_NO_PREALLOC));
    create("lpm value 0", lpm_attr(8, 0, 10, F_NO_PREALLOC));
    /* Not the largest value Linux takes: trie_alloc fills each CPU's cache
       with a node of it, 4 MiB that the machine may not have in one piece. */
    create("lpm value 4096", lpm_attr(8, 4096, 10, F_NO_PREALLOC));
    create("lpm value too big", lpm_attr(8, (1 << 22) - 279, 10, F_NO_PREALLOC));
    create("lpm entries 0", lpm_attr(8, 4, 0, F_NO_PREALLOC));
    create("lpm preallocated", lpm_attr(8, 4, 10, 0));
    create("lpm zero seed", lpm_attr(8, 4, 10, F_NO_PREALLOC | F_ZERO_SEED));
    create("lpm mmapable", lpm_attr(8, 4, 10, F_NO_PREALLOC | F_MMAPABLE));
    create("lpm numa", lpm_attr(8, 4, 10, F_NO_PREALLOC | F_NUMA_NODE));
    create("lpm read only", lpm_attr(8, 4, 10, F_NO_PREALLOC | F_RDONLY_PROG));
    create("lpm both prog access", lpm_attr(8, 4, 10, F_NO_PREALLOC | F_RDONLY_PROG | F_WRONLY_PROG));

    int fd = make(TYPE_LPM_TRIE, 8, 4, 6, F_NO_PREALLOC);
    say("lpm empty memlock %llu", memlock(fd));
    order("lpm empty", fd);
    holds(fd, 192, 168, 0, 1, 32);
    say("lpm put /16 %ld", lpm_put(fd, 192, 168, 0, 0, 16, 1, NOEXIST));
    say("lpm put /24 %ld", lpm_put(fd, 192, 168, 0, 0, 24, 2, ANY));
    say("lpm put 128/24 %ld", lpm_put(fd, 192, 168, 128, 0, 24, 3, ANY));
    say("lpm put 1/24 %ld", lpm_put(fd, 192, 168, 1, 0, 24, 5, ANY));
    say("lpm four memlock %llu", memlock(fd));
    holds(fd, 192, 168, 0, 7, 32);
    holds(fd, 192, 168, 1, 7, 32);
    holds(fd, 192, 168, 128, 1, 32);
    holds(fd, 192, 168, 200, 1, 32);
    holds(fd, 192, 168, 0, 0, 23);
    holds(fd, 192, 168, 0, 0, 15);
    holds(fd, 10, 0, 0, 1, 32);
    holds(fd, 192, 168, 0, 0, 33);
    order("lpm order", fd);
    struct v4 key = v4(192, 168, 0, 0, 23), next;
    long r = elem(MAP_GET_NEXT_KEY, fd, &key, &next, 0);
    say("lpm next of no element %ld %u.%u.%u.%u/%u", r, next.address[0], next.address[1], next.address[2],
        next.address[3], next.length);
    key = v4(0, 0, 0, 0, 40);
    r = elem(MAP_GET_NEXT_KEY, fd, &key, &next, 0);
    say("lpm next of a long prefix %ld %u.%u.%u.%u/%u", r, next.address[0], next.address[1],
        next.address[2], next.address[3], next.length);

    say("lpm put again noexist %ld", lpm_put(fd, 192, 168, 0, 0, 16, 9, NOEXIST));
    say("lpm put /23 exist %ld", lpm_put(fd, 192, 168, 0, 0, 23, 4, EXIST));
    say("lpm put /23 %ld", lpm_put(fd, 192, 168, 0, 0, 23, 4, NOEXIST));
    holds(fd, 192, 168, 0, 0, 23);
    say("lpm put /33 %ld", lpm_put(fd, 192, 168, 0, 0, 33, 4, ANY));
    say("lpm put flag 3 %ld", lpm_put(fd, 10, 0, 0, 0, 8, 4, 3));
    say("lpm put lock %ld", lpm_put(fd, 10, 0, 0, 0, 8, 4, ELEM_F_LOCK));
    say("lpm put 10/8 %ld", lpm_put(fd, 10, 1, 2, 3, 8, 6, ANY));
    say("lpm full %ld", lpm_put(fd, 11, 0, 0, 0, 8, 7, ANY));
    say("lpm full exist %ld", lpm_put(fd, 11, 0, 0, 0, 8, 7, EXIST));
    say("lpm full replace %ld", lpm_put(fd, 10, 9, 9, 9, 8, 8, EXIST));
    order("lpm full", fd);
    say("lpm six memlock %llu", memlock(fd));

    say("lpm delete /23 %ld", lpm_take(fd, 192, 168, 0, 0, 23));
    say("lpm delete /23 again %ld", lpm_take(fd, 192, 168, 0, 0, 23));
    say("lpm delete /33 %ld", lpm_take(fd, 192, 168, 0, 0, 33));
    say("lpm delete 2/24 %ld", lpm_take(fd, 192, 168, 2, 0, 24));
    say("lpm delete /24 %ld", lpm_take(fd, 192, 168, 0, 0, 24));
    say("lpm delete /16 %ld", lpm_take(fd, 192, 168, 0, 0, 16));
    holds(fd, 192, 168, 0, 9, 32);
    holds(fd, 192, 168, 1, 9, 32);
    order("lpm after deletes", fd);
    say("lpm three memlock %llu", memlock(fd));
    uint32_t value;
    key = v4(10, 0, 0, 0, 8);
    say("lpm lookup and delete %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, fd, &key, &value, 0));
    say("lpm lookup lock %ld", elem(MAP_LOOKUP_ELEM, fd, &key, &value, ELEM_F_LOCK));
    say("lpm delete null %ld", elem(MAP_DELETE_ELEM, fd, NULL, NULL, 0));

    /* Batches: the generic ones, which follow the next keys. */
    struct v4 keys[8], out, in;
    uint32_t values[8], count = 2;
    memset(keys, 0, sizeof keys);
    r = batch(MAP_LOOKUP_BATCH, fd, NULL, &out, keys, values, &count, 0);
    say("lpm lookup batch %ld count %u %u.%u.%u.%u/%u=%u %u.%u.%u.%u/%u=%u last /%u", r, count,
        keys[0].address[0], keys[0].address[1], keys[0].address[2], keys[0].address[3], keys[0].length,
        values[0], keys[1].address[0], keys[1].address[1], keys[1].address[2], keys[1].address[3],
        keys[1].length, values[1], out.length);
    in = out;
    count = 8;
    r = batch(MAP_LOOKUP_BATCH, fd, &in, &out, keys, values, &count, 0);
    say("lpm lookup batch rest %ld count %u %u.%u.%u.%u/%u=%u", r, count, keys[0].address[0],
        keys[0].address[1], keys[0].address[2], keys[0].address[3], keys[0].length, values[0]);
    count = 2;
    r = batch(MAP_LOOKUP_AND_DELETE_BATCH, fd, NULL, &out, keys, values, &count, 0);
    say("lpm lookup and delete batch %ld count %u", r, count);
    keys[0] = v4(172, 16, 0, 0, 12);
    keys[1] = v4(172, 16, 0, 0, 40);
    keys[2] = v4(172, 17, 0, 0, 16);
    values[0] = 20;
    values[1] = 21;
    values[2] = 22;
    count = 3;
    r = batch(MAP_UPDATE_BATCH, fd, NULL, NULL, keys, values, &count, 0);
    say("lpm update batch %ld count %u", r, count);
    holds(fd, 172, 16, 5, 5, 32);
    keys[1] = v4(192, 168, 1, 0, 24);
    count = 3;
    r = batch(MAP_DELETE_BATCH, fd, NULL, NULL, keys, NULL, &count, 0);
    say("lpm delete batch %ld count %u", r, count);
    order("lpm after batches", fd);
    close(fd);

    /* Longer keys: 17 bytes of data, past the first 8 and 16. */
    fd = make(TYPE_LPM_TRIE, 4 + 17, 1, 4, F_NO_PREALLOC);
    struct {
        uint32_t length;
        unsigned char data[17];
    } __attribute__((packed)) long_key;
    const struct {
        uint32_t length;
        unsigned char last;
    } puts_[] = {{129, 0x80}, {136, 0x00}, {64, 0x11}};
    for (unsigned i = 0; i < sizeof puts_ / sizeof puts_[0]; i++) {
        long_key.length = puts_[i].length;
        memset(long_key.data, 0xab, 16);
        long_key.data[16] = puts_[i].last;
        unsigned char v = (unsigned char)(i + 1);
        say("lpm long put /%u %ld", puts_[i].length, elem(MAP_UPDATE_ELEM, fd, &long_key, &v, ANY));
    }
    const unsigned char lasts[] = {0xff, 0x00, 0x7f, 0x80};
    for (unsigned i = 0; i < sizeof lasts; i++) {
        long_key.length = 136;
        memset(long_key.data, 0xab, 16);
        long_key.data[16] = lasts[i];
        unsigned char v = 0;
        r = elem(MAP_LOOKUP_ELEM, fd, &long_key, &v, 0);
        say("lpm long lookup %#x %ld %u", lasts[i], r, v);
    }
    long_key.data[3] = 0;
    unsigned char v = 0;
    say("lpm long lookup off at byte 3 %ld", elem(MAP_LOOKUP_ELEM, fd, &long_key, &v, 0));
    printf("lpm long order");
    r = elem(MAP_GET_NEXT_KEY, fd, NULL, &long_key, 0);
    while (r == 0) {
        printf(" /%u:%02x", long_key.length, long_key.data[16]);
        r = elem(MAP_GET_NEXT_KEY, fd, &long_key, &long_key, 0);
    }
    printf(" end %ld\n", r);
    say("lpm long memlock %llu", memlock(fd));
    close(fd);
    return 0;
}

static union attr outer_attr(uint32_t type, uint32_t key, uint32_t value, uint32_t entries, uint32_t flags, int inner) {
    union attr a = map_attr(type, key, value, entries, flags);
    a.inner_map_fd = (uint32_t)inner;
    return a;
}

static int outer(uint32_t type, uint32_t key, uint32_t entries, uint32_t flags, int inner) {
    union attr a = outer_attr(type, key, 4, entries, flags, inner);
    long fd = bpf(MAP_CREATE, &a, sizeof a);
    if (fd < 0) {
        say("outer %ld", fd);
        exit(1);
    }
    return (int)fd;
}

/* An update of key to the map of descriptor fd. */
static long hold(int map, uint32_t key, int fd, uint64_t flags) {
    uint32_t value = (uint32_t)fd;
    return elem(MAP_UPDATE_ELEM, map, &key, &value, flags);
}

/* A lookup of key: the error, or whether it gives the ID of fd's map. */
static void holding(const char *name, int map, uint32_t key, int fd) {
    uint32_t id = 0;
    long r = elem(MAP_LOOKUP_ELEM, map, &key, &id, 0);
    say("%s %ld same %d", name, r, r == 0 && id == id_of(fd));
}

static int case_maps(void) {
    int inner = make(TYPE_ARRAY, 4, 8, 4, 0);
    int hash = make(TYPE_HASH, 4, 8, 4, 0);
    int closed = dup(inner);
    close(closed);

    /* The value is a descriptor, and the template another map's. */
    create("array of maps value 8", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 8, 4, 0, inner));
    create("hash of maps value 8", outer_attr(TYPE_HASH_OF_MAPS, 4, 8, 4, 0, inner));
    create("array of maps rdonly prog", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, F_RDONLY_PROG, inner));
    create("array of maps wronly prog", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, F_WRONLY_PROG, inner));
    create("hash of maps rdonly prog", outer_attr(TYPE_HASH_OF_MAPS, 4, 4, 4, F_RDONLY_PROG, inner));
    create("array of maps inner map flag", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, F_INNER_MAP, inner));
    create("array of maps mmapable", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, F_MMAPABLE, inner));
    create("array of maps key 8", outer_attr(TYPE_ARRAY_OF_MAPS, 8, 4, 4, 0, inner));
    create("array of maps no entries", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 0, 0, inner));
    create("hash of maps no entries", outer_attr(TYPE_HASH_OF_MAPS, 4, 4, 0, 0, inner));
    create("array of maps closed inner", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, 0, closed));
    create("hash of maps closed inner", outer_attr(TYPE_HASH_OF_MAPS, 4, 4, 4, 0, closed));
    create("array of maps file inner", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, 0, 1));
    create("hash of maps value 8 closed inner", outer_attr(TYPE_HASH_OF_MAPS, 4, 8, 4, 0, closed));
    int nested = outer(TYPE_ARRAY_OF_MAPS, 4, 2, 0, inner);
    create("array of maps of maps", outer_attr(TYPE_ARRAY_OF_MAPS, 4, 4, 4, 0, nested));
    create("hash of maps of maps", outer_attr(TYPE_HASH_OF_MAPS, 4, 4, 4, 0, nested));
    close(nested);

    /* An array of maps: maps like the template, by index. */
    int array = outer(TYPE_ARRAY_OF_MAPS, 4, 3, 0, inner);
    int same = make(TYPE_ARRAY, 4, 8, 4, 0);
    int longer = make(TYPE_ARRAY, 4, 8, 5, 0);
    int wider = make(TYPE_ARRAY, 4, 16, 4, 0);
    int readonly = make(TYPE_ARRAY, 4, 8, 4, F_RDONLY);
    int mappable = make(TYPE_ARRAY, 4, 8, 4, F_MMAPABLE);
    say("array of maps the template %ld", hold(array, 0, inner, ANY));
    say("array of maps another like it %ld", hold(array, 1, same, ANY));
    say("array of maps more entries %ld", hold(array, 2, longer, ANY));
    say("array of maps wider values %ld", hold(array, 2, wider, ANY));
    say("array of maps read only %ld", hold(array, 2, readonly, ANY));
    say("array of maps mappable %ld", hold(array, 2, mappable, ANY));
    say("array of maps a hash %ld", hold(array, 2, hash, ANY));
    say("array of maps itself %ld", hold(array, 2, array, ANY));
    say("array of maps closed %ld", hold(array, 2, closed, ANY));
    say("array of maps a file %ld", hold(array, 2, 1, ANY));
    say("array of maps noexist %ld", hold(array, 2, same, NOEXIST));
    say("array of maps exist %ld", hold(array, 0, same, EXIST));
    say("array of maps past the end %ld", hold(array, 3, same, ANY));
    say("array of maps past the end closed %ld", hold(array, 3, closed, ANY));
    say("array of maps noexist closed %ld", hold(array, 2, closed, NOEXIST));
    say("array of maps lock %ld", hold(array, 2, same, ELEM_F_LOCK));
    holding("array of maps lookup 0", array, 0, inner);
    holding("array of maps lookup 1", array, 1, same);
    holding("array of maps lookup 2", array, 2, same);
    holding("array of maps lookup 3", array, 3, same);
    keys("array of maps", array);
    uint32_t k = 2, next = 0;
    say("array of maps next of the last %ld", elem(MAP_GET_NEXT_KEY, array, &k, &next, 0));
    k = 7;
    long r = elem(MAP_GET_NEXT_KEY, array, &k, &next, 0);
    say("array of maps next past the end %ld %u", r, next);
    uint32_t got = 0;
    say("array of maps lookup and delete %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, array, &k, &got, 0));

    /* The map stays while the outer map holds it, and goes on delete. */
    int kept = make(TYPE_ARRAY, 4, 8, 4, 0);
    uint32_t kept_id = id_of(kept);
    say("array of maps kept %ld", hold(array, 2, kept, ANY));
    close(kept);
    long again = fd_by_id(kept_id, 0);
    say("kept after its descriptor closes %s", again >= 0 ? "fd" : "error");
    if (again >= 0) close((int)again);
    holding("array of maps lookup kept", array, 2, -1);
    k = 2;
    say("array of maps delete %ld", elem(MAP_DELETE_ELEM, array, &k, NULL, 0));
    say("kept after delete %ld", fd_by_id(kept_id, 0));
    say("array of maps delete again %ld", elem(MAP_DELETE_ELEM, array, &k, NULL, 0));
    k = 3;
    say("array of maps delete past the end %ld", elem(MAP_DELETE_ELEM, array, &k, NULL, 0));
    holding("array of maps lookup deleted", array, 2, same);

    /* Batches: lookups pass over empty indexes; there is no delete. */
    uint32_t bk[4] = {0, 1, 2, 3}, bv[4], gk[4], gv[4], count = 2, in = 0, out = 99;
    bv[0] = (uint32_t)same;
    bv[1] = (uint32_t)inner;
    k = 0;
    elem(MAP_DELETE_ELEM, array, &k, NULL, 0);
    bk[0] = 2;
    bk[1] = 0;
    r = batch(MAP_UPDATE_BATCH, array, NULL, NULL, bk, bv, &count, 0);
    say("array of maps update batch %ld count %u", r, count);
    k = 1;
    elem(MAP_DELETE_ELEM, array, &k, NULL, 0);
    count = 4;
    memset(gk, 0xff, sizeof gk);
    r = batch(MAP_LOOKUP_BATCH, array, NULL, &out, gk, gv, &count, 0);
    say("array of maps lookup batch %ld count %u out %u keys %u %u same %d %d", r, count, out, gk[0], gk[1],
        gv[0] == id_of(inner), gv[1] == id_of(same));
    count = 1;
    out = 99;
    r = batch(MAP_LOOKUP_BATCH, array, NULL, &out, gk, gv, &count, 0);
    say("array of maps lookup batch of one %ld count %u out %u key %u", r, count, out, gk[0]);
    in = 0;
    count = 1;
    out = 99;
    r = batch(MAP_LOOKUP_BATCH, array, &in, &out, gk, gv, &count, 0);
    say("array of maps lookup batch from 0 %ld count %u out %u key %u", r, count, out, gk[0]);
    in = 2;
    count = 4;
    out = 99;
    r = batch(MAP_LOOKUP_BATCH, array, &in, &out, gk, gv, &count, 0);
    say("array of maps lookup batch from the last %ld count %u out %u", r, count, out);
    count = 2;
    bk[0] = 0;
    bk[1] = 1;
    bv[0] = (uint32_t)same;
    bv[1] = (uint32_t)wider;
    r = batch(MAP_UPDATE_BATCH, array, NULL, NULL, bk, bv, &count, 0);
    say("array of maps update batch with a misfit %ld count %u", r, count);
    count = 2;
    say("array of maps delete batch %ld", batch(MAP_DELETE_BATCH, array, NULL, NULL, bk, NULL, &count, 0));
    count = 2;
    say("array of maps lookup and delete batch %ld",
        batch(MAP_LOOKUP_AND_DELETE_BATCH, array, NULL, &out, gk, gv, &count, 0));
    say("array of maps memlock %llu", memlock(array));
    say("array of maps freeze %ld", ({
            union attr f;
            memset(&f, 0, sizeof f);
            f.elem.map_fd = (uint32_t)array;
            bpf(MAP_FREEZE, &f, sizeof f);
        }));
    say("array of maps frozen update %ld", hold(array, 1, same, ANY));
    close(array);

    /* An array template with BPF_F_INNER_MAP takes arrays of any size. */
    int any = make(TYPE_ARRAY, 4, 8, 4, F_INNER_MAP);
    int any_longer = make(TYPE_ARRAY, 4, 8, 9, F_INNER_MAP);
    array = outer(TYPE_ARRAY_OF_MAPS, 4, 2, 0, any);
    say("inner map flag longer %ld", hold(array, 0, any_longer, ANY));
    say("inner map flag without it %ld", hold(array, 0, longer, ANY));
    close(array);
    close(any);
    close(any_longer);

    /* The access flags are the descriptor's, not the map's. */
    struct map_info mi;
    memset(&mi, 0, sizeof mi);
    union attr q;
    memset(&q, 0, sizeof q);
    q.info.bpf_fd = (uint32_t)readonly;
    q.info.info_len = sizeof mi;
    q.info.info = (uintptr_t)&mi;
    r = bpf(OBJ_GET_INFO_BY_FD, &q, sizeof q);
    say("read only map %ld flags %u", r, mi.map_flags);
    array = outer(TYPE_ARRAY_OF_MAPS, 4, 2, 0, readonly);
    say("read only template takes another %ld", hold(array, 0, same, ANY));
    close(array);

    /* A hash of maps: a hash's flags, after the descriptor. */
    int map = outer(TYPE_HASH_OF_MAPS, 4, 2, 0, hash);
    int hash2 = make(TYPE_HASH, 4, 8, 4, 0);
    int hash_longer = make(TYPE_HASH, 4, 8, 9, 0);
    int hash_lazy = make(TYPE_HASH, 4, 8, 4, F_NO_PREALLOC);
    say("hash of maps the template %ld", hold(map, 10, hash, ANY));
    say("hash of maps more entries %ld", hold(map, 11, hash_longer, ANY));
    say("hash of maps no prealloc %ld", hold(map, 11, hash_lazy, ANY));
    say("hash of maps an array %ld", hold(map, 11, inner, ANY));
    say("hash of maps closed %ld", hold(map, 11, closed, ANY));
    say("hash of maps closed with bad flags %ld", hold(map, 11, closed, 3));
    say("hash of maps misfit with bad flags %ld", hold(map, 11, inner, 7));
    say("hash of maps bad flags %ld", hold(map, 11, hash2, 3));
    say("hash of maps lock %ld", hold(map, 11, hash2, ELEM_F_LOCK));
    say("hash of maps noexist %ld", hold(map, 10, hash2, NOEXIST));
    say("hash of maps exist %ld", hold(map, 11, hash2, EXIST));
    say("hash of maps another %ld", hold(map, 11, hash2, NOEXIST));
    say("hash of maps full %ld", hold(map, 12, hash2, ANY));
    say("hash of maps replace when full %ld", hold(map, 10, hash2, EXIST));
    holding("hash of maps lookup 10", map, 10, hash2);
    holding("hash of maps lookup 11", map, 11, hash2);
    holding("hash of maps lookup 12", map, 12, hash2);
    keys("hash of maps", map);
    k = 10;
    say("hash of maps lookup and delete %ld", elem(MAP_LOOKUP_AND_DELETE_ELEM, map, &k, &got, 0));
    say("hash of maps delete %ld", elem(MAP_DELETE_ELEM, map, &k, NULL, 0));
    say("hash of maps delete again %ld", elem(MAP_DELETE_ELEM, map, &k, NULL, 0));
    keys("hash of maps after delete", map);
    close(map);

    /* Its batches are a hash's. */
    map = outer(TYPE_HASH_OF_MAPS, 4, 8, F_NO_PREALLOC, hash);
    say("hash of maps no prealloc memlock empty %llu", memlock(map));
    uint32_t hk[3] = {5, 6, 7}, hv[3] = {(uint32_t)hash, (uint32_t)hash2, (uint32_t)hash};
    count = 3;
    r = batch(MAP_UPDATE_BATCH, map, NULL, NULL, hk, hv, &count, 0);
    say("hash of maps update batch %ld count %u", r, count);
    say("hash of maps no prealloc memlock %llu", memlock(map));
    uint32_t pairs[8][2];
    uint32_t lk[8], lv[8];
    count = 8;
    r = batch(MAP_LOOKUP_BATCH, map, NULL, &out, lk, lv, &count, 0);
    for (uint32_t i = 0; i < count && i < 8; i++) {
        pairs[i][0] = lk[i];
        pairs[i][1] = lv[i] == id_of(hash) ? 1 : lv[i] == id_of(hash2) ? 2 : 0;
    }
    qsort(pairs, count < 8 ? count : 8, sizeof pairs[0], compare);
    printf("hash of maps lookup batch %ld count %u", r, count);
    for (uint32_t i = 0; i < count && i < 8; i++) printf(" %u:%u", pairs[i][0], pairs[i][1]);
    putchar('\n');
    fflush(stdout);
    uint32_t gone[1] = {6};
    count = 1;
    r = batch(MAP_DELETE_BATCH, map, NULL, NULL, gone, NULL, &count, 0);
    say("hash of maps delete batch %ld count %u", r, count);
    count = 8;
    r = batch(MAP_LOOKUP_AND_DELETE_BATCH, map, NULL, &out, lk, lv, &count, 0);
    say("hash of maps lookup and delete batch %ld count %u", r, count);
    keys("hash of maps emptied", map);
    close(map);

    close(inner);
    close(hash);
    close(same);
    close(longer);
    close(wider);
    close(readonly);
    close(mappable);
    close(hash2);
    close(hash_longer);
    close(hash_lazy);
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
    if (!strcmp(mode, "bpf-lru")) return case_lru();
    if (!strcmp(mode, "bpf-queue")) return case_queue();
    if (!strcmp(mode, "bpf-bloom")) return case_bloom();
    if (!strcmp(mode, "bpf-lpm")) return case_lpm();
    if (!strcmp(mode, "bpf-maps")) return case_maps();
    if (!strcmp(mode, "bpf-prog-load")) return case_prog_load();
    return 2;
}
