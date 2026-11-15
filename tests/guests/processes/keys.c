/* The key retention service, compared with Linux: add_key, request_key and
   keyctl on user, logon and keyring keys, the thread, process, session and
   user keyrings, possession, permissions and quotas.

   Every case starts a new anonymous session keyring, so that what the
   session it was started in holds does not show. Serial numbers are
   random, so the outputs give only whether two are the same, and the
   lengths and contents of what is read; describe strings name owners,
   which are root's or nobody's on both sides. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREAD -1
#define PROCESS -2
#define SESSION -3
#define USER -4
#define USER_SESSION -5

static char *self;

static long e(long r) { return r < 0 ? -errno : r; }

static long add_key(const char *type, const char *description, const void *payload, size_t len,
                    long keyring) {
    return e(syscall(SYS_add_key, type, description, payload, len, keyring));
}
static long request_key(const char *type, const char *description, const char *callout,
                        long keyring) {
    return e(syscall(SYS_request_key, type, description, callout, keyring));
}
static long keyctl(long option, unsigned long a2, unsigned long a3, unsigned long a4,
                   unsigned long a5) {
    return e(syscall(SYS_keyctl, option, a2, a3, a4, a5));
}
static long id_of(long special, int create) { return keyctl(0, special, create, 0, 0); }

/* A result: the value for a length or 0, "serial" for a serial number. */
static void show(const char *label, long r) {
    if (r > 1000)
        printf("%s: serial\n", label);
    else
        printf("%s: %ld\n", label, r);
}
static void same(const char *label, long a, long b) {
    printf("%s: %s\n", label, a > 0 && a == b ? "same" : a > 0 && b > 0 ? "different" : "error");
}
static void describe(const char *label, long id) {
    char text[512];
    memset(text, 0, sizeof text);
    long r = keyctl(6, id, (unsigned long)text, sizeof text, 0);
    if (r < 0)
        printf("%s: %ld\n", label, r);
    else
        printf("%s: %ld %s\n", label, r, text);
}
static void read_key(const char *label, long id, size_t len) {
    char data[256];
    memset(data, '.', sizeof data);
    long r = keyctl(11, id, (unsigned long)data, len, 0);
    if (r < 0 || r > (long)len) {
        printf("%s: %ld untouched=%d\n", label, r, data[0] == '.');
        return;
    }
    printf("%s: %ld %.*s\n", label, r, (int)r, data);
}
/* The serial numbers keyring `id` links, as indices of `known`, -1 for
   others, sorted as they come (the order is Linux's hash order). */
static void links(const char *label, long id, const long *known, int count) {
    int32_t serials[64];
    long r = keyctl(11, id, (unsigned long)serials, sizeof serials, 0);
    printf("%s: %ld", label, r);
    if (r > 0) {
        int marks[64] = {0};
        for (long i = 0; i < r / 4; i++)
            for (int k = 0; k < count; k++)
                if (serials[i] == known[k]) marks[k]++;
        printf(" [");
        for (int k = 0; k < count; k++) printf("%d", marks[k]);
        printf("]");
    }
    printf("\n");
}
static void start_session(void) {
    if (keyctl(1, 0, 0, 0, 0) < 0) {
        printf("join failed\n");
        exit(1);
    }
}

static int case_calls(void) {
    start_session();
    long session = id_of(SESSION, 0);
    show("session", session);
    describe("describe session", session);
    char caps[4] = {9, 9, 9, 9};
    show("capabilities", keyctl(31, (unsigned long)caps, sizeof caps, 0, 0));
    printf("capabilities beyond: %d %d\n", caps[2], caps[3]);

    long k1 = add_key("user", "k1", "hello", 5, SESSION);
    show("add user", k1);
    describe("describe user", k1);
    read_key("read", k1, 100);
    read_key("read short", k1, 2);
    show("read length", keyctl(11, k1, 0, 0, 0));
    same("add again updates", add_key("user", "k1", "world!", 6, SESSION), k1);
    read_key("read updated", k1, 100);
    show("update", keyctl(2, k1, (unsigned long)"abc", 3, 0));
    read_key("read update", k1, 100);
    show("update empty", keyctl(2, k1, 0, 0, 0));
    show("update too long", keyctl(2, k1, (unsigned long)"x", 4097, 0));
    show("update keyring", keyctl(2, session, (unsigned long)"x", 1, 0));
    same("search", keyctl(10, SESSION, (unsigned long)"user", (unsigned long)"k1", 0), k1);
    show("search missing", keyctl(10, SESSION, (unsigned long)"user", (unsigned long)"none", 0));
    show("search unknown type", keyctl(10, SESSION, (unsigned long)"nonesuch", (unsigned long)"k1", 0));
    same("search finds the keyring itself",
         keyctl(10, SESSION, (unsigned long)"keyring", (unsigned long)"_ses", 0), session);
    same("request", request_key("user", "k1", NULL, 0), k1);
    show("request missing", request_key("user", "none", NULL, 0));
    show("request unknown type", request_key("nonesuch", "k1", NULL, 0));
    show("request no description", request_key("user", NULL, NULL, 0));

    show("unknown type", add_key("nonesuch", "x", "1", 1, SESSION));
    show("kernel type", add_key(".request_key_auth", "x", "1", 1, SESSION));
    show("empty type", add_key("", "x", "1", 1, SESSION));
    show("long type", add_key("0123456789012345678901234567890123", "x", "1", 1, SESSION));
    show("dot keyring", add_key("keyring", ".x", NULL, 0, SESSION));
    show("dot user", add_key("user", ".x", "1", 1, SESSION) > 0);
    show("no description", add_key("user", NULL, "1", 1, SESSION));
    show("empty description", add_key("user", "", "1", 1, SESSION));
    show("empty payload", add_key("user", "e", NULL, 0, SESSION));
    show("big payload", add_key("user", "b", "1", 32768, SESSION));
    show("huge payload", add_key("user", "b", "1", 1 << 20, SESSION));
    show("bad payload", add_key("user", "b", (void *)8, 10, SESSION));
    show("keyring payload", add_key("keyring", "r", "1", 1, SESSION));
    show("into a user key", add_key("user", "x", "1", 1, k1));
    show("into nothing", add_key("user", "x", "1", 1, 0));
    show("into group", add_key("user", "x", "1", 1, -6));
    show("into requestor", add_key("user", "x", "1", 1, -8));
    show("into -12", add_key("user", "x", "1", 1, -12));
    show("into missing", add_key("user", "x", "1", 1, 0x7ffffff0));

    long logon = add_key("logon", "svc:a", "secret", 6, SESSION);
    show("logon", logon);
    describe("describe logon", logon);
    read_key("read logon", logon, 100);
    show("logon no prefix", add_key("logon", "nocolon", "1", 1, SESSION));
    show("logon empty prefix", add_key("logon", ":x", "1", 1, SESSION));
    show("update logon", keyctl(2, logon, (unsigned long)"new", 3, 0));

    show("security", keyctl(17, k1, 0, 0, 0));
    char label[4] = {9, 9, 9, 9};
    show("security buffer", keyctl(17, k1, (unsigned long)label, sizeof label, 0));
    printf("security text: %d %d\n", label[0], label[1]);
    show("unknown option", keyctl(99, 0, 0, 0, 0));
    show("instantiate", keyctl(12, k1, (unsigned long)"x", 1, 0));
    show("instantiate huge", keyctl(12, k1, 0, 1 << 20, 0));
    show("negate", keyctl(13, k1, 10, 0, 0));
    show("reject zero", keyctl(19, k1, 10, 0, 0));
    show("reject restart", keyctl(19, k1, 10, 512, 0));
    show("reject", keyctl(19, k1, 10, 22, 0));
    struct iovec iov = {"x", 1};
    show("instantiate iov", keyctl(20, k1, (unsigned long)&iov, 1, 0));
    show("instantiate iov many", keyctl(20, k1, (unsigned long)&iov, 1025, 0));
    show("assume negative", keyctl(16, (unsigned long)-1, 0, 0, 0));
    show("assume none", keyctl(16, 0, 0, 0, 0));
    show("assume key", keyctl(16, k1, 0, 0, 0));
    show("pkey query arg", keyctl(24, k1, 1, 0, 0));
    show("restrict nothing", keyctl(29, session, 0, (unsigned long)"x", 0));
    show("move flags", keyctl(30, k1, SESSION, SESSION, 2));
    show("move same", keyctl(30, k1, SESSION, SESSION, 0));
    show("keyring id -12", id_of(-12, 0));
    show("keyring id group", id_of(-6, 0));
    show("keyring id auth", id_of(-7, 0));
    show("keyring id requestor", id_of(-8, 0));
    show("keyring id zero", id_of(0, 0));
    show("keyring id missing", id_of(0x7ffffff0, 0));
    show("join dot", keyctl(1, (unsigned long)".x", 0, 0, 0));
    show("join empty", keyctl(1, (unsigned long)"", 0, 0, 0));
    show("set default", keyctl(14, (unsigned long)-1, 0, 0, 0));
    show("set default group", keyctl(14, 6, 0, 0, 0));
    show("set default bad", keyctl(14, 8, 0, 0, 0));
    show("set default session", keyctl(14, 3, 0, 0, 0));
    show("set default again", keyctl(14, (unsigned long)-1, 0, 0, 0));
    show("set default back", keyctl(14, 0, 0, 0, 0));
    return 0;
}

static int case_keyrings(void) {
    start_session();
    long session = id_of(SESSION, 0);
    long ring = add_key("keyring", "ring", NULL, 0, SESSION);
    long inner = add_key("keyring", "inner", NULL, 0, ring);
    long k1 = add_key("user", "k1", "one", 3, ring);
    long k2 = add_key("user", "k2", "two", 3, inner);
    long known[] = {ring, inner, k1, k2};
    describe("describe ring", ring);
    links("session links", session, known, 4);
    links("ring links", ring, known, 4);
    show("read ring odd", keyctl(11, ring, (unsigned long)known, 3, 0));
    show("read ring length", keyctl(11, ring, 0, 0, 0));
    same("search nested", keyctl(10, SESSION, (unsigned long)"user", (unsigned long)"k2", 0), k2);
    same("request nested", request_key("user", "k2", NULL, 0), k2);
    show("link into itself", keyctl(8, ring, ring, 0, 0));
    show("link cycle", keyctl(8, session, inner, 0, 0));
    show("link", keyctl(8, k2, SESSION, 0, 0));
    links("session after link", session, known, 4);
    show("link again", keyctl(8, k2, SESSION, 0, 0));
    long k2b = add_key("user", "k2", "other", 5, ring);
    same("same name elsewhere is another key", k2b, k2);
    show("link displaces", keyctl(8, k2b, SESSION, 0, 0));
    links("session displaced", session, known, 4);
    show("link into a user key", keyctl(8, k1, k1, 0, 0));
    /* Linux puts a key whose last link goes after an RCU grace period, so
       k1 stays linked elsewhere for what follows. */
    keyctl(8, k1, PROCESS, 0, 0);
    show("unlink", keyctl(9, k1, ring, 0, 0));
    show("unlink again", keyctl(9, k1, ring, 0, 0));
    show("unlink from a user key", keyctl(9, k1, k2, 0, 0));
    show("unlinked is still linked elsewhere", keyctl(6, k1, 0, 0, 0) > 0);

    long ring2 = add_key("keyring", "ring2", NULL, 0, SESSION);
    long k3 = add_key("user", "k3", "three", 5, ring);
    long known2[] = {ring, ring2, k3};
    show("move", keyctl(30, k3, ring, ring2, 0));
    links("ring after move", ring, known2, 3);
    links("ring2 after move", ring2, known2, 3);
    show("move missing", keyctl(30, k3, ring, ring2, 0));
    long k3b = add_key("user", "k3", "again", 5, ring);
    show("move exclusive", keyctl(30, k3b, ring, ring2, 1));
    show("move displaces", keyctl(30, k3b, ring, ring2, 0));
    show("move cycle", keyctl(30, ring, SESSION, inner, 0));

    show("restrict", keyctl(29, ring2, 0, 0, 0));
    show("restrict again", keyctl(29, ring2, 0, 0, 0));
    show("link restricted", keyctl(8, k2, ring2, 0, 0));
    show("add restricted", add_key("user", "r", "1", 1, ring2));
    show("restrict by user type", keyctl(29, ring, (unsigned long)"user", (unsigned long)"x", 0));
    show("restrict by unknown type", keyctl(29, ring, (unsigned long)"zzz", (unsigned long)"x", 0));
    show("restrict type alone", keyctl(29, ring, (unsigned long)"user", 0, 0));
    show("restrict a user key", keyctl(29, k2, 0, 0, 0));

    show("clear", keyctl(7, ring2, 0, 0, 0));
    show("cleared", keyctl(11, ring2, 0, 0, 0));
    show("clear a user key", keyctl(7, k2, 0, 0, 0));

    show("revoke", keyctl(3, k2b, 0, 0, 0));
    read_key("read revoked", k2b, 100);
    describe("describe revoked", k2b);
    show("search revoked", keyctl(10, SESSION, (unsigned long)"user", (unsigned long)"k2", 0));
    show("add over revoked", add_key("user", "k2", "new", 3, SESSION) > 0);
    show("revoke ring", keyctl(3, inner, 0, 0, 0));
    show("revoked ring", keyctl(11, inner, 0, 0, 0));
    show("link into revoked", keyctl(8, k2, inner, 0, 0));

    long gone = add_key("user", "gone", "x", 1, SESSION);
    show("invalidate", keyctl(21, gone, 0, 0, 0));
    sleep(1);
    show("invalidated", keyctl(6, gone, 0, 0, 0));

    long brief = add_key("user", "brief", "x", 1, SESSION);
    show("timeout", keyctl(15, brief, 1, 0, 0));
    long kept = add_key("user", "kept", "x", 1, SESSION);
    show("timeout then none", keyctl(15, kept, 1, 0, 0));
    show("no timeout", keyctl(15, kept, 0, 0, 0));
    long renewed = add_key("user", "renewed", "x", 1, SESSION);
    keyctl(15, renewed, 1, 0, 0);
    add_key("user", "renewed", "y", 1, SESSION);
    sleep(2);
    read_key("read expired", brief, 100);
    describe("describe expired", brief);
    show("search expired", keyctl(10, SESSION, (unsigned long)"user", (unsigned long)"brief", 0));
    show("request expired", request_key("user", "brief", NULL, 0));
    read_key("read kept", kept, 100);
    read_key("read renewed by update", renewed, 100);

    show("setperm bad", keyctl(5, k2, 0x40, 0, 0));
    show("setperm none", keyctl(5, k2, 0, 0, 0));
    describe("describe no permission", k2);
    show("search no permission", keyctl(10, SESSION, (unsigned long)"user", (unsigned long)"k2", 0));
    read_key("read no permission", k2, 100);
    show("chown", keyctl(4, k3b, 1234, 4321, 0));
    describe("describe chowned", k3b);
    show("chown nothing", keyctl(4, k3b, (unsigned long)-1, (unsigned long)-1, 0));
    show("setperm view only", keyctl(5, k3b, 0x01000000, 0, 0));
    describe("describe view only", k3b);
    read_key("read possessed", k3b, 100);

    long persistent = keyctl(22, (unsigned long)-1, SESSION, 0, 0);
    show("persistent", persistent);
    describe("describe persistent", persistent);
    same("persistent again", keyctl(22, (unsigned long)-1, SESSION, 0, 0), persistent);
    describe("describe other persistent", keyctl(22, 1234, SESSION, 0, 0));
    show("persistent into a user key", keyctl(22, (unsigned long)-1, k3b, 0, 0));
    return 0;
}

static void *thread_ids(void *arg) {
    long *ids = arg;
    ids[0] = id_of(THREAD, 0);
    ids[1] = id_of(PROCESS, 0);
    ids[2] = id_of(SESSION, 0);
    ids[3] = id_of(THREAD, 1);
    return NULL;
}

static int case_threads(void) {
    start_session();
    long session = id_of(SESSION, 0);
    show("thread missing", id_of(THREAD, 0));
    show("process missing", id_of(PROCESS, 0));
    long thread = id_of(THREAD, 1);
    long process = id_of(PROCESS, 1);
    show("thread", thread);
    show("process", process);
    describe("describe thread", thread);
    describe("describe process", process);
    same("thread again", id_of(THREAD, 0), thread);
    same("session", id_of(SESSION, 1), session);

    long ids[4];
    pthread_t t;
    pthread_create(&t, NULL, thread_ids, ids);
    pthread_join(t, NULL);
    printf("new thread's thread keyring: %s\n", ids[0] > 0 && ids[0] != thread ? "its own" : "?");
    same("new thread's process keyring", ids[1], process);
    same("new thread's session keyring", ids[2], session);

    pid_t child = fork();
    if (child == 0) {
        show("child thread", id_of(THREAD, 0));
        show("child process", id_of(PROCESS, 0));
        same("child session", id_of(SESSION, 0), session);
        long own = id_of(PROCESS, 1);
        printf("child's process keyring: %s\n", own > 0 && own != process ? "its own" : "?");
        _exit(0);
    }
    waitpid(child, NULL, 0);

    long user = id_of(USER, 0);
    long user_session = id_of(USER_SESSION, 0);
    describe("describe user", user);
    describe("describe user session", user_session);
    long known[] = {user};
    links("user session links", user_session, known, 1);

    long named = keyctl(1, (unsigned long)"keys-named", 0, 0, 0);
    show("join named", named);
    describe("describe named", named);
    show("join named again", keyctl(1, (unsigned long)"keys-named", 0, 0, 0));
    start_session();
    same("join named from elsewhere", keyctl(1, (unsigned long)"keys-named", 0, 0, 0), named);
    keyctl(5, named, 0x3f0b0000, 0, 0);
    start_session();
    same("join named searchable", keyctl(1, (unsigned long)"keys-named", 0, 0, 0), named);

    start_session();
    session = id_of(SESSION, 0);
    id_of(THREAD, 1);
    id_of(PROCESS, 1);
    char arg[32];
    snprintf(arg, sizeof arg, "%ld", session);
    child = fork();
    if (child == 0) {
        char *args[] = {"keys", "keys-exec-child", arg, NULL};
        execv(self, args);
        _exit(1);
    }
    int status;
    waitpid(child, &status, 0);
    return 0;
}

static int case_exec_child(const char *session) {
    show("exec thread", id_of(THREAD, 0));
    show("exec process", id_of(PROCESS, 0));
    same("exec session", id_of(SESSION, 0), atol(session));
    return 0;
}

static void *sleeper(void *arg) {
    (void)arg;
    for (;;) pause();
}

static int case_parent(void) {
    start_session();
    pid_t middle = fork();
    if (middle == 0) {
        start_session();
        long before = id_of(SESSION, 0);
        int pipefd[2];
        pipe(pipefd);
        pid_t child = fork();
        if (child == 0) {
            long own = keyctl(1, 0, 0, 0, 0);
            show("to parent", keyctl(18, 0, 0, 0, 0));
            show("to parent again", keyctl(18, 0, 0, 0, 0));
            write(pipefd[1], &own, sizeof own);
            _exit(0);
        }
        long own;
        read(pipefd[0], &own, sizeof own);
        waitpid(child, NULL, 0);
        long after = id_of(SESSION, 0);
        printf("parent's session: %s\n",
               after == own ? "the child's" : after == before ? "unchanged" : "?");
        _exit(0);
    }
    waitpid(middle, NULL, 0);

    /* A parent with two threads keeps its own. */
    middle = fork();
    if (middle == 0) {
        start_session();
        long before = id_of(SESSION, 0);
        long ids[4];
        pthread_t t;
        pthread_create(&t, NULL, sleeper, ids);
        pid_t child = fork();
        if (child == 0) {
            keyctl(1, 0, 0, 0, 0);
            show("to threaded parent", keyctl(18, 0, 0, 0, 0));
            _exit(0);
        }
        waitpid(child, NULL, 0);
        same("threaded parent's session", id_of(SESSION, 0), before);
        _exit(0);
    }
    waitpid(middle, NULL, 0);

    /* A child that took other IDs may not. */
    middle = fork();
    if (middle == 0) {
        start_session();
        pid_t child = fork();
        if (child == 0) {
            setresgid(65534, 65534, 65534);
            setresuid(65534, 65534, 65534);
            keyctl(1, 0, 0, 0, 0);
            show("to parent of other IDs", keyctl(18, 0, 0, 0, 0));
            _exit(0);
        }
        waitpid(child, NULL, 0);
        _exit(0);
    }
    waitpid(middle, NULL, 0);
    return 0;
}

static int case_permissions(void) {
    start_session();
    long root_key = add_key("user", "rootkey", "root", 4, SESSION);
    long ring = add_key("keyring", "rootring", NULL, 0, SESSION);
    long hidden = add_key("user", "hidden", "data", 4, ring);
    /* Kept by the process keyring, which the child does not have. */
    keyctl(8, ring, PROCESS, 0, 0);
    keyctl(9, ring, SESSION, 0, 0);
    pid_t child = fork();
    if (child == 0) {
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        describe("describe possessed", root_key);
        read_key("read possessed", root_key, 100);
        show("update possessed", keyctl(2, root_key, (unsigned long)"x", 1, 0));
        show("setperm not owner", keyctl(5, root_key, 0x3f3f0000, 0, 0));
        show("chown", keyctl(4, root_key, 65534, (unsigned long)-1, 0));
        show("chown group", keyctl(4, root_key, (unsigned long)-1, 65534, 0));
        show("describe unreachable", keyctl(6, ring, 0, 0, 0));
        show("describe unreachable key", keyctl(6, hidden, 0, 0, 0));
        read_key("read unreachable", hidden, 100);
        show("invalidate unreachable", keyctl(21, hidden, 0, 0, 0));
        show("persistent of another", keyctl(22, 0, SESSION, 0, 0));
        show("persistent", keyctl(22, (unsigned long)-1, SESSION, 0, 0) > 0);

        start_session();
        long session = id_of(SESSION, 0);
        describe("describe own session", session);
        describe("describe user keyring", id_of(USER, 0));
        long count = 0, r;
        char payload[100];
        memset(payload, 'p', sizeof payload);
        for (;;) {
            char name[24];
            snprintf(name, sizeof name, "q%ld", count);
            r = add_key("user", name, payload, sizeof payload, SESSION);
            if (r < 0) break;
            count++;
        }
        printf("quota: %ld keys, then %ld\n", count, r);
        show("update past quota", keyctl(2, session, (unsigned long)"x", 1, 0));
        show("clear", keyctl(7, SESSION, 0, 0, 0));
        _exit(0);
    }
    waitpid(child, NULL, 0);

    /* The quota of keys, by a user no other case is (Linux gives back what
       a key took only when its collector frees it, a little later). */
    child = fork();
    if (child == 0) {
        setresgid(65533, 65533, 65533);
        setresuid(65533, 65533, 65533);
        start_session();
        long count = 0, r;
        for (;;) {
            char name[24];
            snprintf(name, sizeof name, "q%ld", count);
            r = add_key("user", name, "1", 1, SESSION);
            if (r < 0) break;
            count++;
        }
        printf("quota of keys: %ld keys, then %ld\n", count, r);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    self = argc > 2 ? argv[2] : "/keys";
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (!strcmp(mode, "keys-calls")) return case_calls();
    if (!strcmp(mode, "keys-keyrings")) return case_keyrings();
    if (!strcmp(mode, "keys-threads")) return case_threads();
    if (!strcmp(mode, "keys-exec-child")) return case_exec_child(self);
    if (!strcmp(mode, "keys-parent")) return case_parent();
    if (!strcmp(mode, "keys-permissions")) return case_permissions();
    printf("unknown mode %s\n", mode);
    return 2;
}
