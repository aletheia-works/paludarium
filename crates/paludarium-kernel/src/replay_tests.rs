//! Cases of the differential guests in `tests/guests/processes`, replayed
//! through the kernel's system calls in the same order, with the guest's own
//! lines. The expected lines are what the guest printed for its mode on
//! native Linux 7.0 (x86-64, Ubuntu 26.04 runner); `diff_processes` still
//! compares the whole guests with Linux on every CI run. A line that needs
//! another process (a fork) is left out, as these tests run one thread.
use super::*;

const HEAP: u64 = 0x700000;
const HEAP_PAGES: u64 = 16;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const FCNTL: u64 = 72;
const READLINK: u64 = 89;

/// One guest thread, its memory and the lines it printed.
struct Guest {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
    top: u64,
    lines: Vec<String>,
}

impl Guest {
    fn new() -> Self {
        let (k, t, m) = setup();
        m.map_shared(
            Some(GuestAddr(HEAP)),
            HEAP_PAGES * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        Self {
            k,
            t,
            m,
            top: HEAP,
            lines: Vec::new(),
        }
    }
    /// A system call's result as the guest's `-errno` convention gives it.
    fn call(&mut self, n: u64, a: [u64; 6]) -> i64 {
        syscall(&mut self.k, &mut self.t, &self.m, n, a) as i64
    }
    fn alloc(&mut self, len: usize) -> u64 {
        let at = self.top;
        self.top += (len as u64 + 15) & !15;
        assert!(self.top <= HEAP + HEAP_PAGES * PAGE_SIZE);
        at
    }
    fn put(&mut self, bytes: &[u8]) -> u64 {
        let at = self.alloc(bytes.len());
        self.m.write(GuestAddr(at), bytes).unwrap();
        at
    }
    fn get(&self, at: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.m.read(GuestAddr(at), &mut bytes).unwrap();
        bytes
    }
    fn u32_at(&self, at: u64) -> u32 {
        u32::from_le_bytes(self.get(at, 4).try_into().unwrap())
    }
    fn u64_at(&self, at: u64) -> u64 {
        self.m.read_u64(GuestAddr(at)).unwrap()
    }
    fn say(&mut self, line: String) {
        self.lines.push(line);
    }
    fn open(&mut self, path: &str) -> i64 {
        let path = self.put(format!("{path}\0").as_bytes());
        self.call(OPEN, [path, 0, 0, 0, 0, 0])
    }
    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }
    /// Every line printed, against the native ones.
    fn check(&self, native: &str) {
        let native: Vec<_> = native.trim().lines().collect();
        let lines: Vec<_> = self.lines.iter().map(String::as_str).collect();
        assert_eq!(lines, native);
    }
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// `tests/guests/processes/bpf.c`: maps, their elements and batches.
mod bpf {
    use super::*;

    const BPF: u64 = 321;
    const MAP_CREATE: u64 = 0;
    const MAP_LOOKUP_ELEM: u64 = 1;
    const MAP_UPDATE_ELEM: u64 = 2;
    const MAP_DELETE_ELEM: u64 = 3;
    const MAP_GET_NEXT_KEY: u64 = 4;
    const OBJ_GET_INFO_BY_FD: u64 = 15;
    const MAP_LOOKUP_AND_DELETE_ELEM: u64 = 21;
    const MAP_FREEZE: u64 = 22;
    const MAP_LOOKUP_BATCH: u64 = 24;
    const MAP_LOOKUP_AND_DELETE_BATCH: u64 = 25;
    const MAP_UPDATE_BATCH: u64 = 26;
    const MAP_DELETE_BATCH: u64 = 27;
    const HASH: u32 = 1;
    const ARRAY: u32 = 2;
    const F_NO_COMMON_LRU: u32 = 1 << 1;
    const F_NUMA_NODE: u32 = 1 << 2;
    const F_RDONLY: u32 = 1 << 3;
    const F_WRONLY: u32 = 1 << 4;
    const F_ZERO_SEED: u32 = 1 << 6;
    const F_RDONLY_PROG: u32 = 1 << 7;
    const F_WRONLY_PROG: u32 = 1 << 8;
    const F_PRESERVE_ELEMS: u32 = 1 << 11;
    const ANY: u64 = 0;
    const NOEXIST: u64 = 1;
    const EXIST: u64 = 2;
    const ELEM_F_LOCK: u64 = 4;
    /// The guest's `union attr`.
    const ATTR: usize = 128;
    /// Where the guest's `0` would be: no address.
    const NULL: u64 = 0;

    fn map_attr(kind: u32, key: u32, value: u32, entries: u32, flags: u32) -> [u8; ATTR] {
        let mut a = [0; ATTR];
        put32(&mut a, 0, kind);
        put32(&mut a, 4, key);
        put32(&mut a, 8, value);
        put32(&mut a, 12, entries);
        put32(&mut a, 16, flags);
        a
    }
    fn name(a: &mut [u8; ATTR], name: &[u8]) {
        a[28..44].fill(0);
        a[28..28 + name.len()].copy_from_slice(name);
    }
    impl Guest {
        fn bpf_at(&mut self, cmd: u64, attr: u64, size: u64) -> i64 {
            self.call(BPF, [cmd, attr, size, 0, 0, 0])
        }
        fn bpf(&mut self, cmd: u64, attr: &[u8]) -> i64 {
            let at = self.put(attr);
            self.bpf_at(cmd, at, attr.len() as u64)
        }
        fn create(&mut self, label: &str, attr: [u8; ATTR]) {
            let fd = self.bpf(MAP_CREATE, &attr);
            if fd >= 0 {
                self.close(fd);
                self.say(format!("{label} fd"));
            } else {
                self.say(format!("{label} {fd}"));
            }
        }
        fn make(&mut self, kind: u32, key: u32, value: u32, entries: u32, flags: u32) -> i64 {
            let fd = self.bpf(MAP_CREATE, &map_attr(kind, key, value, entries, flags));
            assert!(fd >= 0, "make {fd}");
            fd
        }
        fn elem(&mut self, cmd: u64, fd: i64, key: u64, value: u64, flags: u64) -> i64 {
            let mut a = [0; ATTR];
            put32(&mut a, 0, fd as u32);
            put64(&mut a, 8, key);
            put64(&mut a, 16, value);
            put64(&mut a, 24, flags);
            self.bpf(cmd, &a)
        }
        /// A 4-byte key or 8-byte value in memory.
        fn word(&mut self, value: u32) -> u64 {
            self.put(&value.to_le_bytes())
        }
        fn quad(&mut self, value: u64) -> u64 {
            self.put(&value.to_le_bytes())
        }
        /// The guest's `keys`: a hash's keys from MAP_GET_NEXT_KEY, sorted.
        fn keys(&mut self, label: &str, fd: i64) {
            let next = self.word(0);
            let key = self.word(0);
            let mut found = Vec::new();
            let mut r = self.elem(MAP_GET_NEXT_KEY, fd, NULL, next, 0);
            while r == 0 && found.len() < 32 {
                let n = self.u32_at(next);
                found.push(n);
                self.m.write(GuestAddr(key), &n.to_le_bytes()).unwrap();
                r = self.elem(MAP_GET_NEXT_KEY, fd, key, next, 0);
            }
            found.sort_unstable();
            let mut line = format!("{label} end {r} keys");
            for k in found {
                line += &format!(" {k}");
            }
            self.say(line);
        }
        fn fcntl(&mut self, fd: i64, cmd: u64) -> i64 {
            self.call(FCNTL, [fd as u64, cmd, 0, 0, 0, 0])
        }
        /// The guest's `batch`, with the count it reads back.
        #[allow(clippy::too_many_arguments)]
        fn batch(
            &mut self,
            cmd: u64,
            fd: i64,
            within: u64,
            out: u64,
            keys: u64,
            values: u64,
            count: &mut u32,
            flags: u64,
        ) -> i64 {
            let mut a = [0; ATTR];
            put64(&mut a, 0, within);
            put64(&mut a, 8, out);
            put64(&mut a, 16, keys);
            put64(&mut a, 24, values);
            put32(&mut a, 32, *count);
            put32(&mut a, 36, fd as u32);
            put64(&mut a, 48, flags);
            let at = self.put(&a);
            let r = self.bpf_at(cmd, at, ATTR as u64);
            *count = self.u32_at(at + 32);
            r
        }
    }

    #[test]
    fn calls() {
        let mut g = Guest::new();
        let a = map_attr(ARRAY, 4, 8, 4, 0);
        let r = g.bpf(1000, &a);
        g.say(format!("unknown command {r}"));
        let r = g.bpf_at(MAP_CREATE, NULL, ATTR as u64);
        g.say(format!("fault {r}"));
        let at = g.put(&a);
        let r = g.bpf_at(MAP_CREATE, at, 4097);
        g.say(format!("size past a page {r}"));
        let mut big = [0u8; 256];
        big[..ATTR].copy_from_slice(&a);
        let fd = g.bpf(MAP_CREATE, &big[..200]);
        g.say(format!(
            "size 200 zero tail {}",
            if fd >= 0 { "fd" } else { "error" }
        ));
        if fd >= 0 {
            g.close(fd);
        }
        big[199] = 1;
        let r = g.bpf(MAP_CREATE, &big[..200]);
        g.say(format!("size 200 tail {r}"));
        let r = g.bpf(MAP_CREATE, &a[..4]);
        g.say(format!("size 4 {r}"));

        g.create("unspecified type", map_attr(0, 4, 8, 4, 0));
        g.create("unknown type", map_attr(1000, 4, 8, 4, 0));
        g.create("array key 8", map_attr(ARRAY, 8, 8, 4, 0));
        g.create("array value 0", map_attr(ARRAY, 4, 0, 4, 0));
        g.create("array entries 0", map_attr(ARRAY, 4, 8, 0, 0));
        g.create("array unknown flag", map_attr(ARRAY, 4, 8, 4, 1 << 20));
        g.create("array no prealloc", map_attr(ARRAY, 4, 8, 4, 1));
        g.create("array preserve", map_attr(ARRAY, 4, 8, 4, F_PRESERVE_ELEMS));
        g.create(
            "both prog access",
            map_attr(ARRAY, 4, 8, 4, F_RDONLY_PROG | F_WRONLY_PROG),
        );
        g.create("both access", map_attr(ARRAY, 4, 8, 4, F_RDONLY | F_WRONLY));
        let mut a = map_attr(ARRAY, 4, 8, 4, F_NUMA_NODE);
        put32(&mut a, 24, 5000);
        g.create("numa node", a);
        let mut a = map_attr(ARRAY, 4, 8, 4, 0);
        put64(&mut a, 64, 1);
        g.create("extra", a);
        let mut a = map_attr(ARRAY, 4, 8, 4, 0);
        name(&mut a, b"a-b");
        g.create("name with dash", a);
        name(&mut a, b"0123456789abcdef");
        g.create("name of 16", a);
        name(&mut a, b"map_1.x");
        g.create("name", a);
        let mut a = map_attr(ARRAY, 4, 8, 4, 0);
        put32(&mut a, 52, 1);
        g.create("btf key only", a);
        put32(&mut a, 56, 1);
        let null = g.open("/dev/null");
        put32(&mut a, 48, null as u32);
        g.create("btf of a file", a);
        g.close(null);
        let mut a = map_attr(ARRAY, 4, 8, 4, 0);
        put32(&mut a, 60, 1);
        g.create("vmlinux value", a);
        g.create("hash key 0", map_attr(HASH, 0, 8, 4, 0));
        g.create("hash value 0", map_attr(HASH, 4, 0, 4, 0));
        g.create("hash entries 0", map_attr(HASH, 4, 8, 0, 0));
        g.create(
            "hash no common lru",
            map_attr(HASH, 4, 8, 4, F_NO_COMMON_LRU),
        );
        g.create("hash mmapable", map_attr(HASH, 4, 8, 4, 1 << 10));
        g.create("hash zero seed", map_attr(HASH, 4, 8, 4, F_ZERO_SEED));
        g.create("hash too big", map_attr(HASH, 4, 1 << 22, 4, 0));
        g.create("hash", map_attr(HASH, 4, 8, 4, 0));

        // The descriptor.
        let map = g.make(ARRAY, 4, 8, 4, 0);
        let cloexec = (g.fcntl(map, 1) & 1 != 0) as i32;
        let access = g.fcntl(map, 3) & 3;
        g.say(format!("cloexec {cloexec} access {access}"));
        let path = g.put(format!("/proc/self/fd/{map}\0").as_bytes());
        let link = g.alloc(64);
        let length = g.call(READLINK, [path, link, 63, 0, 0, 0]);
        let link = String::from_utf8(g.get(link, length.max(0) as usize)).unwrap();
        g.say(format!("link {link}"));
        let buffer = g.alloc(8);
        let read = g.call(READ, [map as u64, buffer, 8, 0, 0, 0]);
        let write = g.call(WRITE, [map as u64, buffer, 8, 0, 0, 0]);
        g.say(format!("read {read} write {write}"));
        let readonly = g.make(ARRAY, 4, 8, 4, F_RDONLY);
        let writeonly = g.make(ARRAY, 4, 8, 4, F_WRONLY);
        let (r, w) = (g.fcntl(readonly, 3) & 3, g.fcntl(writeonly, 3) & 3);
        g.say(format!("access read only {r} write only {w}"));

        // The fdinfo, but for memlock and map_id.
        let info = g.open(&format!("/proc/self/fdinfo/{map}"));
        assert!(info >= 0);
        let text = g.alloc(4096);
        let length = g.call(READ, [info as u64, text, 4096, 0, 0, 0]);
        let text = String::from_utf8(g.get(text, length as usize)).unwrap();
        g.close(info);
        for line in text.lines() {
            let wanted = line.starts_with("map_") && !line.starts_with("map_id");
            let also = ["key_size", "value_size", "max_entries", "frozen"]
                .iter()
                .any(|p| line.starts_with(p));
            if wanted || also {
                g.say(line.to_owned());
            }
        }

        // BPF_OBJ_GET_INFO_BY_FD, up to map_extra.
        let mut a = map_attr(HASH, 4, 8, 7, 0);
        name(&mut a, b"named");
        let named = g.bpf(MAP_CREATE, &a);
        let mi = g.alloc(88);
        let mut q = [0u8; ATTR];
        put32(&mut q, 0, named as u32);
        put32(&mut q, 4, 88);
        put64(&mut q, 8, mi);
        let at = g.put(&q);
        let r = g.bpf_at(OBJ_GET_INFO_BY_FD, at, ATTR as u64);
        let mi_name = g.get(mi + 24, 16);
        let mi_name =
            String::from_utf8(mi_name.split(|&b| b == 0).next().unwrap().to_vec()).unwrap();
        let line = format!(
            "info {r} len {} type {} key {} value {} entries {} flags {} name {mi_name} id {}",
            g.u32_at(at + 4),
            g.u32_at(mi),
            g.u32_at(mi + 8),
            g.u32_at(mi + 12),
            g.u32_at(mi + 16),
            g.u32_at(mi + 20),
            (g.u32_at(mi + 4) > 0) as i32
        );
        g.say(line);
        put32(&mut q, 4, 8);
        let mi = g.alloc(88);
        put64(&mut q, 8, mi);
        let at = g.put(&q);
        let r = g.bpf_at(OBJ_GET_INFO_BY_FD, at, ATTR as u64);
        let line = format!(
            "short info {r} len {} type {} key {}",
            g.u32_at(at + 4),
            g.u32_at(mi),
            g.u32_at(mi + 8)
        );
        g.say(line);
        put32(&mut q, 0, 999);
        let r = g.bpf(OBJ_GET_INFO_BY_FD, &q);
        g.say(format!("info of no fd {r}"));
        put32(&mut q, 0, 0);
        let r = g.bpf(OBJ_GET_INFO_BY_FD, &q);
        g.say(format!("info of a file {r}"));
        put32(&mut q, 0, named as u32);
        q[20] = 1;
        let r = g.bpf(OBJ_GET_INFO_BY_FD, &q);
        g.say(format!("info with more {r}"));
        for fd in [named, readonly, writeonly, map] {
            g.close(fd);
        }
        g.check(
            "
unknown command -22
fault -14
size past a page -7
size 200 zero tail fd
size 200 tail -7
size 4 -22
unspecified type -22
unknown type -22
array key 8 -22
array value 0 -22
array entries 0 -22
array unknown flag -22
array no prealloc -22
array preserve -22
both prog access -22
both access -22
numa node -22
extra -22
name with dash -22
name of 16 -22
name fd
btf key only -22
btf of a file -22
vmlinux value -22
hash key 0 -22
hash value 0 -22
hash entries 0 -22
hash no common lru -22
hash mmapable -22
hash zero seed fd
hash too big -7
hash fd
cloexec 1 access 2
link anon_inode:bpf-map
read -22 write -22
access read only 0 write only 1
map_type:\t2
key_size:\t4
value_size:\t8
max_entries:\t4
map_flags:\t0x0
map_extra:\t0x0
frozen:\t0
info 0 len 88 type 1 key 4 value 8 entries 7 flags 0 name named id 1
short info 0 len 8 type 1 key 0
info of no fd -77
info of a file -22
info with more -22
",
        );
    }

    #[test]
    fn elements() {
        let mut g = Guest::new();
        let array = g.make(ARRAY, 4, 8, 4, 0);
        let key = g.word(1);
        let value = g.quad(0x1122334455667788);
        let got = g.quad(0);
        let set_key = |g: &mut Guest, k: u32| g.m.write(GuestAddr(key), &k.to_le_bytes()).unwrap();
        let r = g.elem(MAP_LOOKUP_ELEM, array, key, got, 0);
        let v = g.u64_at(got);
        g.say(format!("array lookup fresh {r} {v:x}"));
        let r = g.elem(MAP_UPDATE_ELEM, array, key, value, ANY);
        g.say(format!("array update {r}"));
        let r = g.elem(MAP_LOOKUP_ELEM, array, key, got, 0);
        let v = g.u64_at(got);
        g.say(format!("array lookup {r} {v:x}"));
        for (label, flags) in [
            ("array noexist", NOEXIST),
            ("array exist", EXIST),
            ("array flags 3", 3),
            ("array lock", ELEM_F_LOCK),
            ("array high flags", 1 << 40),
        ] {
            let r = g.elem(MAP_UPDATE_ELEM, array, key, value, flags);
            g.say(format!("{label} {r}"));
        }
        set_key(&mut g, 4);
        let r = g.elem(MAP_UPDATE_ELEM, array, key, value, ANY);
        g.say(format!("array past the end {r}"));
        let r = g.elem(MAP_LOOKUP_ELEM, array, key, got, 0);
        g.say(format!("array lookup past the end {r}"));
        let r = g.elem(MAP_DELETE_ELEM, array, key, NULL, 0);
        g.say(format!("array delete {r}"));
        let r = g.elem(MAP_LOOKUP_AND_DELETE_ELEM, array, key, got, 0);
        g.say(format!("array lookup and delete {r}"));
        let r = g.elem(MAP_LOOKUP_ELEM, array, key, got, 1);
        g.say(format!("lookup flags {r}"));
        let r = g.elem(MAP_LOOKUP_ELEM, array, NULL, got, 0);
        g.say(format!("lookup no key {r}"));
        set_key(&mut g, 1);
        let r = g.elem(MAP_LOOKUP_ELEM, array, key, NULL, 0);
        g.say(format!("lookup no value {r}"));
        let r = g.elem(MAP_DELETE_ELEM, array, key, got, 0);
        g.say(format!("delete with a value {r}"));
        let next = g.word(99);
        let r = g.elem(MAP_GET_NEXT_KEY, array, NULL, next, 0);
        let n = g.u32_at(next);
        g.say(format!("array first {r} {n}"));
        set_key(&mut g, 2);
        let r = g.elem(MAP_GET_NEXT_KEY, array, key, next, 0);
        let n = g.u32_at(next);
        g.say(format!("array next {r} {n}"));
        set_key(&mut g, 3);
        let r = g.elem(MAP_GET_NEXT_KEY, array, key, next, 0);
        g.say(format!("array last {r}"));
        set_key(&mut g, 77);
        let r = g.elem(MAP_GET_NEXT_KEY, array, key, next, 0);
        let n = g.u32_at(next);
        g.say(format!("array next of none {r} {n}"));
        let null = g.open("/dev/null");
        let r = g.elem(MAP_LOOKUP_ELEM, null, key, got, 0);
        g.say(format!("lookup of a file {r}"));
        let r = g.elem(MAP_LOOKUP_ELEM, 999, key, got, 0);
        g.say(format!("lookup of no fd {r}"));
        g.close(null);

        // Access through the descriptor, and freezing.
        let readonly = g.make(ARRAY, 4, 8, 4, F_RDONLY);
        let writeonly = g.make(ARRAY, 4, 8, 4, F_WRONLY);
        set_key(&mut g, 0);
        let u = g.elem(MAP_UPDATE_ELEM, readonly, key, value, 0);
        let l = g.elem(MAP_LOOKUP_ELEM, readonly, key, got, 0);
        g.say(format!("read only update {u} lookup {l}"));
        let l = g.elem(MAP_LOOKUP_ELEM, writeonly, key, got, 0);
        let n = g.elem(MAP_GET_NEXT_KEY, writeonly, NULL, next, 0);
        let u = g.elem(MAP_UPDATE_ELEM, writeonly, key, value, 0);
        g.say(format!("write only lookup {l} next {n} update {u}"));
        let r = g.elem(MAP_FREEZE, readonly, NULL, NULL, 0);
        g.say(format!("freeze read only {r}"));
        let r = g.elem(MAP_FREEZE, array, NULL, NULL, 0);
        g.say(format!("freeze {r}"));
        let r = g.elem(MAP_FREEZE, array, NULL, NULL, 0);
        g.say(format!("freeze again {r}"));
        set_key(&mut g, 1);
        let l = g.elem(MAP_LOOKUP_ELEM, array, key, got, 0);
        let u = g.elem(MAP_UPDATE_ELEM, array, key, value, 0);
        let v = g.u64_at(got);
        g.say(format!("frozen update {u} lookup {l} {v:x}"));
        let r = g.elem(MAP_FREEZE, writeonly, key, NULL, 0);
        g.say(format!("freeze with a key {r}"));
        for fd in [readonly, writeonly, array] {
            g.close(fd);
        }

        // A hash.
        let hash = g.make(HASH, 4, 8, 3, 0);
        set_key(&mut g, 10);
        let r = g.elem(MAP_LOOKUP_ELEM, hash, key, got, 0);
        g.say(format!("hash lookup none {r}"));
        for (label, flags) in [
            ("hash exist none", EXIST),
            ("hash noexist", NOEXIST),
            ("hash noexist again", NOEXIST),
        ] {
            let r = g.elem(MAP_UPDATE_ELEM, hash, key, value, flags);
            g.say(format!("{label} {r}"));
        }
        g.m.write_u64(GuestAddr(value), 20).unwrap();
        let r = g.elem(MAP_UPDATE_ELEM, hash, key, value, EXIST);
        g.say(format!("hash exist {r}"));
        let r = g.elem(MAP_LOOKUP_ELEM, hash, key, got, 0);
        let v = g.u64_at(got);
        g.say(format!("hash lookup {r} {v}"));
        let r = g.elem(MAP_UPDATE_ELEM, hash, key, value, 3);
        g.say(format!("hash flags 3 {r}"));
        for k in 11..=12 {
            set_key(&mut g, k);
            g.elem(MAP_UPDATE_ELEM, hash, key, value, ANY);
        }
        set_key(&mut g, 13);
        let r = g.elem(MAP_UPDATE_ELEM, hash, key, value, ANY);
        g.say(format!("hash full {r}"));
        set_key(&mut g, 12);
        let r = g.elem(MAP_UPDATE_ELEM, hash, key, value, ANY);
        g.say(format!("hash full replace {r}"));
        g.keys("hash", hash);
        set_key(&mut g, 99);
        let r = g.elem(MAP_GET_NEXT_KEY, hash, key, next, 0);
        let n = g.u32_at(next);
        g.say(format!(
            "hash next of none {r} first {}",
            (10..=12).contains(&n) as i32
        ));
        set_key(&mut g, 11);
        let r = g.elem(MAP_DELETE_ELEM, hash, key, NULL, 0);
        g.say(format!("hash delete {r}"));
        let r = g.elem(MAP_DELETE_ELEM, hash, key, NULL, 0);
        g.say(format!("hash delete again {r}"));
        set_key(&mut g, 12);
        g.m.write_u64(GuestAddr(got), 0).unwrap();
        let r = g.elem(MAP_LOOKUP_AND_DELETE_ELEM, hash, key, got, 0);
        let v = g.u64_at(got);
        g.say(format!("hash lookup and delete {r} {v}"));
        let r = g.elem(MAP_LOOKUP_AND_DELETE_ELEM, hash, key, got, 0);
        g.say(format!("hash lookup and delete again {r}"));
        let r = g.elem(MAP_LOOKUP_AND_DELETE_ELEM, hash, key, got, 1);
        g.say(format!("hash lookup and delete flags {r}"));
        g.keys("hash after", hash);
        g.close(hash);
        g.check(
            "
array lookup fresh 0 0
array update 0
array lookup 0 1122334455667788
array noexist -17
array exist 0
array flags 3 -22
array lock -22
array high flags -22
array past the end -7
array lookup past the end -2
array delete -22
array lookup and delete -524
lookup flags -22
lookup no key -14
lookup no value -14
delete with a value -22
array first 0 0
array next 0 3
array last -2
array next of none 0 0
lookup of a file -22
lookup of no fd -9
read only update -1 lookup 0
write only lookup -1 next -1 update 0
freeze read only -1
freeze 0
freeze again -1
frozen update -1 lookup 0 1122334455667788
freeze with a key -22
hash lookup none -2
hash exist none -2
hash noexist 0
hash noexist again -17
hash exist 0
hash lookup 0 20
hash flags 3 -22
hash full -7
hash full replace 0
hash end -2 keys 10 11 12
hash next of none 0 first 1
hash delete 0
hash delete again -2
hash lookup and delete 0 20
hash lookup and delete again -2
hash lookup and delete flags -22
hash after end -2 keys 10
",
        );
    }

    #[test]
    fn batch() {
        let mut g = Guest::new();
        let array = g.make(ARRAY, 4, 8, 5, 0);
        let k = g.put(&(0u32..8).flat_map(u32::to_le_bytes).collect::<Vec<_>>());
        let v = g.put(&(100u64..108).flat_map(u64::to_le_bytes).collect::<Vec<_>>());
        let out = g.word(99);
        let mut count = 3;
        let r = g.batch(MAP_UPDATE_BATCH, array, NULL, NULL, k, v, &mut count, 0);
        g.say(format!("array update batch {r} count {count}"));
        count = 8;
        let r = g.batch(MAP_UPDATE_BATCH, array, NULL, NULL, k, v, &mut count, 0);
        g.say(format!("array update batch past the end {r} count {count}"));
        count = 0;
        let r = g.batch(MAP_UPDATE_BATCH, array, NULL, NULL, k, v, &mut count, 0);
        g.say(format!("array update batch of none {r}"));
        let gk = g.put(&[0xff; 32]);
        let gv = g.alloc(64);
        count = 3;
        let r = g.batch(MAP_LOOKUP_BATCH, array, NULL, out, gk, gv, &mut count, 0);
        let line = format!(
            "array lookup batch {r} count {count} out {} keys {} {} {} values {} {} {}",
            g.u32_at(out),
            g.u32_at(gk),
            g.u32_at(gk + 4),
            g.u32_at(gk + 8),
            g.u64_at(gv),
            g.u64_at(gv + 8),
            g.u64_at(gv + 16)
        );
        g.say(line);
        let within = g.word(g.u32_at(out));
        count = 3;
        let r = g.batch(MAP_LOOKUP_BATCH, array, within, out, gk, gv, &mut count, 0);
        let line = format!(
            "array lookup batch on {r} count {count} out {} keys {} {}",
            g.u32_at(out),
            g.u32_at(gk),
            g.u32_at(gk + 4)
        );
        g.say(line);
        count = 3;
        let r = g.batch(MAP_DELETE_BATCH, array, NULL, NULL, k, v, &mut count, 0);
        g.say(format!("array delete batch {r}"));
        count = 3;
        let r = g.batch(
            MAP_LOOKUP_AND_DELETE_BATCH,
            array,
            NULL,
            out,
            gk,
            gv,
            &mut count,
            0,
        );
        g.say(format!("array lookup and delete batch {r}"));
        count = 1;
        let r = g.batch(MAP_LOOKUP_BATCH, array, NULL, out, gk, gv, &mut count, 1);
        g.say(format!("batch flags {r}"));
        g.close(array);

        let hash = g.make(HASH, 4, 8, 8, 0);
        count = 5;
        let r = g.batch(MAP_UPDATE_BATCH, hash, NULL, NULL, k, v, &mut count, 0);
        g.say(format!("hash update batch {r} count {count}"));
        g.keys("hash", hash);
        // Addresses at the top of the address space wrap, and fault.
        count = 2;
        let r = g.batch(MAP_UPDATE_BATCH, hash, NULL, NULL, !3, v, &mut count, 0);
        g.say(format!("hash update batch from the top {r} count {count}"));
        count = 8;
        g.m.write(GuestAddr(gk), &[0; 32]).unwrap();
        let r = g.batch(MAP_LOOKUP_BATCH, hash, NULL, out, gk, gv, &mut count, 0);
        let mut keys: Vec<_> = (0..count as u64).map(|i| g.u32_at(gk + 4 * i)).collect();
        keys.sort_unstable();
        keys.resize(5.max(keys.len()), 0);
        let line = format!(
            "hash lookup batch {r} count {count} keys {} {} {} {} {}",
            keys[0], keys[1], keys[2], keys[3], keys[4]
        );
        g.say(line);
        count = 1;
        let r = g.batch(MAP_LOOKUP_BATCH, hash, NULL, out, gk, gv, &mut count, 1);
        g.say(format!("hash lookup batch flags {r}"));
        let within = g.word(1 << 20);
        count = 8;
        let r = g.batch(MAP_LOOKUP_BATCH, hash, within, out, gk, gv, &mut count, 0);
        g.say(format!("hash lookup batch past the buckets {r}"));
        let gone = g.put(&[1, 0, 0, 0, 3, 0, 0, 0]);
        count = 2;
        let r = g.batch(
            MAP_DELETE_BATCH,
            hash,
            NULL,
            NULL,
            gone,
            NULL,
            &mut count,
            0,
        );
        g.say(format!("hash delete batch {r} count {count}"));
        count = 2;
        let r = g.batch(
            MAP_DELETE_BATCH,
            hash,
            NULL,
            NULL,
            gone,
            NULL,
            &mut count,
            0,
        );
        g.say(format!("hash delete batch again {r} count {count}"));
        g.keys("hash after delete", hash);
        count = 8;
        let r = g.batch(
            MAP_LOOKUP_AND_DELETE_BATCH,
            hash,
            NULL,
            out,
            gk,
            gv,
            &mut count,
            0,
        );
        g.say(format!("hash lookup and delete batch {r} count {count}"));
        g.keys("hash emptied", hash);
        g.close(hash);
        g.check(
            "
array update batch 0 count 3
array update batch past the end -7 count 5
array update batch of none 0
array lookup batch 0 count 3 out 2 keys 0 1 2 values 100 101 102
array lookup batch on -2 count 2 out 4 keys 3 4
array delete batch -524
array lookup and delete batch -524
batch flags 0
hash update batch 0 count 5
hash end -2 keys 0 1 2 3 4
hash update batch from the top -14 count 0
hash lookup batch -2 count 5 keys 0 1 2 3 4
hash lookup batch flags -22
hash lookup batch past the buckets -2
hash delete batch 0 count 2
hash delete batch again -2 count 0
hash after delete end -2 keys 0 2 4
hash lookup and delete batch -2 count 3
hash emptied end -2 keys
",
        );
    }
}

/// `tests/guests/processes/perf.c`: perf_event_open's checks and events.
mod perf {
    use super::*;

    const PERF_EVENT_OPEN: u64 = 298;
    /// struct perf_event_attr as of PERF_ATTR_SIZE_VER8.
    const ATTR: usize = 136;
    const INHERIT: u64 = 1 << 1;
    const EXCLUDE_KERNEL: u64 = 1 << 5;
    const EXCLUDE_HV: u64 = 1 << 6;
    const FREQ: u64 = 1 << 10;
    const ENABLE_ON_EXEC: u64 = 1 << 12;
    const USE_CLOCKID: u64 = 1 << 25;
    const AUX_OUTPUT: u64 = 1 << 31;
    const INHERIT_THREAD: u64 = 1 << 35;
    const REMOVE_ON_EXEC: u64 = 1 << 36;
    const ATTR_SIGTRAP: u64 = 1 << 37;
    const SAMPLE_READ: u64 = 1 << 4;
    const SAMPLE_BRANCH_STACK: u64 = 1 << 11;
    const SAMPLE_REGS_USER: u64 = 1 << 12;
    const SAMPLE_STACK_USER: u64 = 1 << 13;
    const SAMPLE_WEIGHT: u64 = 1 << 14;
    const SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;
    const FLAG_PID_CGROUP: u64 = 4;
    /// The guest's -1 as an int argument.
    const NONE: u64 = u64::MAX;

    /// A change to an attribute, for one case.
    type Change = fn(&mut [u8; ATTR]);
    /// A software event of this thread, counting user time only.
    fn software(config: u64) -> [u8; ATTR] {
        let mut a = [0; ATTR];
        put32(&mut a, 0, 1);
        put32(&mut a, 4, ATTR as u32);
        put64(&mut a, 8, config);
        put64(&mut a, 40, EXCLUDE_KERNEL | EXCLUDE_HV);
        a
    }
    fn flags(a: &mut [u8; ATTR], add: u64) {
        let old = u64::from_le_bytes(a[40..48].try_into().unwrap());
        put64(a, 40, old | add);
    }
    impl Guest {
        fn open_event(&mut self, attr: u64, pid: u64, cpu: u64, group: u64, flags: u64) -> i64 {
            self.call(PERF_EVENT_OPEN, [attr, pid, cpu, group, flags, 0])
        }
        fn attempt(&mut self, label: &str, a: &[u8], pid: u64, cpu: u64, group: u64, flags: u64) {
            let at = self.put(a);
            let fd = self.open_event(at, pid, cpu, group, flags);
            if fd >= 0 {
                self.close(fd);
                self.say(format!("{label} fd"));
            } else {
                self.say(format!("{label} {fd}"));
            }
        }
    }

    #[test]
    fn calls() {
        let mut g = Guest::new();
        let mut a = software(1);
        g.attempt("flags", &a, 0, NONE, NONE, 0x10);
        let r = g.open_event(0, 0, NONE, NONE, 0);
        g.say(format!("fault {r}"));
        // Sizes: 0 is the first one's, 64 bytes.
        put32(&mut a, 4, 0);
        g.attempt("size 0", &a, 0, NONE, NONE, 0);
        for (label, size) in [("size 1", 1), ("size 0x2000", 0x2000)] {
            let mut a = software(1);
            put32(&mut a, 4, size);
            let at = g.put(&a);
            let r = g.open_event(at, 0, NONE, NONE, 0);
            let written = (g.u32_at(at + 4) != size) as i32;
            g.say(format!("{label} {r} written {written}"));
        }
        let mut big = [0u8; 512];
        let mut a = software(1);
        put32(&mut a, 4, 300);
        big[..ATTR].copy_from_slice(&a);
        let at = g.put(&big);
        let fd = g.open_event(at, 0, NONE, NONE, 0);
        g.say(format!(
            "size 300 zero tail {}",
            if fd >= 0 { "fd" } else { "error" }
        ));
        if fd >= 0 {
            g.close(fd);
        }
        g.m.write(GuestAddr(at + 299), &[1]).unwrap();
        let fd = g.open_event(at, 0, NONE, NONE, 0);
        let written = (g.u32_at(at + 4) != 300) as i32;
        g.say(format!("size 300 tail {fd} written {written}"));

        // The fields perf_copy_attr checks.
        let cases: [(&str, Change); 13] = [
            ("reserved flag", |a| flags(a, 1 << 63)),
            ("reserved 2", |a| {
                a[110..112].copy_from_slice(&1u16.to_le_bytes())
            }),
            ("reserved 3", |a| put32(a, 116, 1 << 5)),
            ("sample type", |a| put64(a, 24, 1 << 40)),
            ("read format", |a| put64(a, 32, 1 << 9)),
            ("branch only plm", |a| {
                put64(a, 24, SAMPLE_BRANCH_STACK);
                put64(a, 72, 1);
            }),
            ("branch unknown", |a| {
                put64(a, 24, SAMPLE_BRANCH_STACK);
                put64(a, 72, 1 << 40);
            }),
            ("branch software", |a| {
                put64(a, 24, SAMPLE_BRANCH_STACK);
                put64(a, 72, 1 << 3);
            }),
            ("regs none", |a| put64(a, 24, SAMPLE_REGS_USER)),
            ("regs ds", |a| {
                put64(a, 24, SAMPLE_REGS_USER);
                put64(a, 80, 1 << 12);
            }),
            ("regs reserved", |a| {
                put64(a, 24, SAMPLE_REGS_USER);
                put64(a, 80, 1 << 26);
            }),
            ("regs xmm", |a| {
                put64(a, 24, SAMPLE_REGS_USER);
                put64(a, 80, 1 << 32);
            }),
            ("regs", |a| {
                put64(a, 24, SAMPLE_REGS_USER);
                put64(a, 80, 0xff);
            }),
        ];
        for (label, change) in cases {
            let mut a = software(1);
            change(&mut a);
            g.attempt(label, &a, 0, NONE, NONE, 0);
        }
        let mut a = software(1);
        put64(&mut a, 24, SAMPLE_STACK_USER);
        put32(&mut a, 88, 65535);
        g.attempt("stack too big", &a, 0, NONE, NONE, 0);
        put32(&mut a, 88, 12);
        g.attempt("stack unaligned", &a, 0, NONE, NONE, 0);
        let mut a = software(1);
        put64(&mut a, 24, SAMPLE_WEIGHT | SAMPLE_WEIGHT_STRUCT);
        g.attempt("weights", &a, 0, NONE, NONE, 0);
        for (label, add) in [
            ("inherit thread", INHERIT_THREAD),
            ("remove and enable on exec", REMOVE_ON_EXEC | ENABLE_ON_EXEC),
        ] {
            let mut a = software(1);
            flags(&mut a, add);
            g.attempt(label, &a, 0, NONE, NONE, 0);
        }
        let mut a = software(1);
        flags(&mut a, ATTR_SIGTRAP);
        g.attempt("sigtrap", &a, 0, NONE, NONE, 0);
        flags(&mut a, REMOVE_ON_EXEC);
        g.attempt("sigtrap of no task", &a, NONE, 0, NONE, 0);

        // Then sys_perf_event_open's own.
        let mut a = software(1);
        put64(&mut a, 16, 1 << 63);
        g.attempt("period", &a, 0, NONE, NONE, 0);
        let mut a = software(1);
        flags(&mut a, FREQ);
        put64(&mut a, 16, 1_000_000_000);
        g.attempt("frequency", &a, 0, NONE, NONE, 0);
        let a = software(1);
        g.attempt("cgroup of no cpu", &a, 0, NONE, NONE, FLAG_PID_CGROUP);
        let null = g.open("/dev/null");
        g.attempt("group of a file", &a, 0, NONE, null as u64, 0);
        g.close(null);
        g.attempt("group of no file", &a, 0, NONE, 999, 0);
        g.attempt("no task", &a, 0x7fff_ffff, NONE, NONE, 0);
        g.attempt("no task and no cpu", &a, NONE, NONE, NONE, 0);
        g.attempt("no such cpu", &a, 0, 100_000, NONE, 0);
        g.attempt("cpu -2", &a, 0, (-2i64) as u64, NONE, 0);
        let mut a = software(1);
        flags(&mut a, INHERIT);
        put64(&mut a, 24, SAMPLE_READ);
        g.attempt("inherit sample read", &a, 0, NONE, NONE, 0);
        let mut a = software(1);
        flags(&mut a, AUX_OUTPUT);
        g.attempt("aux output", &a, 0, NONE, NONE, 0);
        let mut a = software(1);
        flags(&mut a, USE_CLOCKID);
        put32(&mut a, 92, 3);
        g.attempt("thread clock", &a, 0, NONE, NONE, 0);
        put32(&mut a, 92, 1);
        g.attempt("monotonic clock", &a, 0, NONE, NONE, 0);

        // The events.
        g.attempt("software 99", &software(99), 0, NONE, NONE, 0);
        g.attempt("software max", &software(12), 0, NONE, NONE, 0);
        for config in 0..=1 {
            let a = software(config);
            let name = if config == 1 {
                "task-clock"
            } else {
                "cpu-clock"
            };
            g.attempt(name, &a, 0, NONE, NONE, 0);
            g.attempt(&format!("{name} of cpu 0"), &a, NONE, 0, NONE, 0);
        }
        g.attempt("dummy", &software(9), 0, NONE, NONE, 0);
        let mut a = software(1);
        put32(&mut a, 0, 1000);
        g.attempt("other type", &a, 0, NONE, NONE, 0);
        g.check(
            "
flags -22
fault -14
size 0 fd
size 1 -7 written 1
size 0x2000 -7 written 1
size 300 zero tail fd
size 300 tail -7 written 1
reserved flag -22
reserved 2 -22
reserved 3 -22
sample type -22
read format -22
branch only plm -22
branch unknown -22
branch software -95
regs none -22
regs ds -22
regs reserved -22
regs xmm -95
regs fd
stack too big -22
stack unaligned -22
weights -22
inherit thread -22
remove and enable on exec -22
sigtrap -22
sigtrap of no task -22
period -22
frequency -22
cgroup of no cpu -22
group of a file -9
group of no file -9
no task -3
no task and no cpu -22
no such cpu -22
cpu -2 -22
inherit sample read -22
aux output -95
thread clock -22
monotonic clock fd
software 99 -2
software max -2
cpu-clock fd
cpu-clock of cpu 0 fd
task-clock fd
task-clock of cpu 0 fd
dummy fd
other type -2
",
        );
    }
}
