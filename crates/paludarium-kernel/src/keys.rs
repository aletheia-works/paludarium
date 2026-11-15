//! The key retention service (`security/keys/`): `add_key`,
//! `request_key` and `keyctl`.
//!
//! A key is a typed, described payload with an owner, a group, a permission
//! mask and a random serial number; a keyring is a key whose payload links
//! other keys. A thread finds keys through its thread, process and session
//! keyrings, and through the keyrings of its user (`_uid.N` and
//! `_uid_ses.N`), which every user namespace keeps in a register; the keys
//! it reaches that way it possesses, which adds the possessor's bits of a
//! key's mask to what it may do. A key lives while a keyring links it or a
//! thread's keyrings hold it: here an [`Arc`] does both, and a key's
//! quota (`kernel.keys.maxkeys` and `maxbytes`, or root's) goes back to
//! its owner when the last one goes.
//!
//! The types are `keyring`, `user` and `logon`, and the kernel is one
//! without `CONFIG_BIG_KEYS`, `CONFIG_KEY_DH_OPERATIONS`,
//! `CONFIG_ASYMMETRIC_KEY_TYPE` and `CONFIG_KEY_NOTIFICATIONS`, with
//! persistent keyrings. `request_key` with callout information finds no
//! `/sbin/request-key` to run, as a system without it: the key it makes
//! is negated for 60 seconds and the call fails with `ENOENT`, so no
//! thread ever holds the authority to instantiate a key.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use paludarium_host::{ClockId, Host};
use paludarium_types::{Errno, GuestAddr};

use crate::credentials::Credentials;
use crate::syscalls::{Context, Outcome};
use crate::users::{INVALID, Ids};

const ENOKEY: Errno = Errno(126);
const EKEYEXPIRED: Errno = Errno(127);
const EKEYREVOKED: Errno = Errno(128);
const EDQUOT: Errno = Errno(122);
const EDEADLK: Errno = Errno(35);
const ELOOP: Errno = Errno(40);

/// The permission bits of each class: view, read, write, search, link and
/// setattr.
const VIEW: u32 = 0x01;
const READ: u32 = 0x02;
const WRITE: u32 = 0x04;
const SEARCH: u32 = 0x08;
const LINK: u32 = 0x10;
const SETATTR: u32 = 0x20;
const ALL: u32 = 0x3f;
const fn possessor(bits: u32) -> u32 {
    bits << 24
}
const fn user(bits: u32) -> u32 {
    bits << 16
}
const fn group(bits: u32) -> u32 {
    bits << 8
}

/// The special keyring IDs (`KEY_SPEC_*`).
const THREAD_KEYRING: i32 = -1;
const PROCESS_KEYRING: i32 = -2;
const SESSION_KEYRING: i32 = -3;
const USER_KEYRING: i32 = -4;
const USER_SESSION_KEYRING: i32 = -5;
const GROUP_KEYRING: i32 = -6;
const REQKEY_AUTH_KEY: i32 = -7;
const REQUESTOR_KEYRING: i32 = -8;
const BPF_KEYRING: i32 = -9;
const DM_VERITY_KEYRING: i32 = -10;
const FS_VERITY_KEYRING: i32 = -11;

/// `KEY_MAX_DESC_SIZE`.
const MAX_DESCRIPTION: usize = 4096;
const PAGE_SIZE: u64 = 4096;
/// `add_key` and an instantiation take at most this much payload.
const MAX_PAYLOAD: u64 = 1024 * 1024 - 1;
/// A `user` or `logon` key holds at most this much.
const MAX_USER_PAYLOAD: usize = 32767;
/// How deep a search goes below the keyring it starts at
/// (`KEYRING_SEARCH_MAX_DEPTH`).
const MAX_DEPTH: usize = 6;
/// `KEYQUOTA_LINK_BYTES`: what a link in a keyring charges its owner.
const LINK_BYTES: u64 = 4;
/// `kernel.keys.gc_delay`: how long an expired key stays linked.
const GC_DELAY: i64 = 5 * 60;
/// How long a negated key lasts (`key_negative_timeout`).
const NEGATIVE_TIMEOUT: i64 = 60;
/// `kernel.keys.persistent_keyring_expiry`.
const PERSISTENT_EXPIRY: i64 = 3 * 24 * 3600;
/// What `KEYCTL_CAPABILITIES` reports: the call itself, persistent
/// keyrings, invalidation, restriction and moving; keyring names and keys
/// kept per user namespace.
const CAPABILITIES: [u8; 2] = [0x01 | 0x02 | 0x20 | 0x40 | 0x80, 0x01 | 0x02];

const CAP_SETUID: u64 = 1 << 7;
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// A key's type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Keyring,
    User,
    /// A `user` key that may not be read back.
    Logon,
    /// `.request_key_auth`, the authority to instantiate a key, which no
    /// key here ever is: searches for it find nothing.
    Authority,
}

impl Kind {
    /// The type a name names (`key_type_lookup`).
    fn named(name: &[u8]) -> Option<Self> {
        match name {
            b"keyring" => Some(Self::Keyring),
            b"user" => Some(Self::User),
            b"logon" => Some(Self::Logon),
            b".request_key_auth" => Some(Self::Authority),
            _ => None,
        }
    }
    fn name(self) -> &'static [u8] {
        match self {
            Self::Keyring => b"keyring",
            Self::User => b"user",
            Self::Logon => b"logon",
            Self::Authority => b".request_key_auth",
        }
    }
    fn readable(self) -> bool {
        matches!(self, Self::Keyring | Self::User)
    }
    fn updatable(self) -> bool {
        matches!(self, Self::User | Self::Logon)
    }
}

/// What a key's quota is charged to its owner: `kernel.keys.maxkeys` and
/// `maxbytes`, or root's.
#[derive(Debug, Default)]
pub(crate) struct Quotas(Mutex<BTreeMap<u32, (u64, u64)>>);

impl Quotas {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u32, (u64, u64)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn limits(uid: u32) -> (u64, u64) {
        if uid == 0 {
            (1_000_000, 25_000_000)
        } else {
            (200, 20_000)
        }
    }
    /// Charges `uid` a key of `bytes`, `EDQUOT` past its quota unless
    /// `overrun`.
    fn charge(&self, uid: u32, bytes: u64, overrun: bool) -> Result<(), Errno> {
        let (keys, max_bytes) = Self::limits(uid);
        let mut table = self.lock();
        let used = table.entry(uid).or_default();
        if !overrun && (used.0 + 1 > keys || used.1 + bytes > max_bytes) {
            return Err(EDQUOT);
        }
        used.0 += 1;
        used.1 += bytes;
        Ok(())
    }
    fn release(&self, uid: u32, bytes: u64) {
        let mut table = self.lock();
        if let Some(used) = table.get_mut(&uid) {
            used.0 = used.0.saturating_sub(1);
            used.1 = used.1.saturating_sub(bytes);
        }
    }
    /// Moves a key of `bytes` from `from` to `to`, `EDQUOT` past `to`'s
    /// quota (`keyctl_chown_key`).
    fn transfer(&self, from: u32, to: u32, bytes: u64) -> Result<(), Errno> {
        let (keys, max_bytes) = Self::limits(to);
        let mut table = self.lock();
        let used = table.entry(to).or_default();
        if used.0 + 1 > keys || used.1 + bytes > max_bytes {
            return Err(EDQUOT);
        }
        used.0 += 1;
        used.1 += bytes;
        if let Some(old) = table.get_mut(&from) {
            old.0 = old.0.saturating_sub(1);
            old.1 = old.1.saturating_sub(bytes);
        }
        Ok(())
    }
    /// Changes what `uid` is charged by `delta` bytes, `EDQUOT` when it
    /// grows past the quota.
    fn adjust(&self, uid: u32, delta: i64) -> Result<(), Errno> {
        let (_, max_bytes) = Self::limits(uid);
        let mut table = self.lock();
        let used = table.entry(uid).or_default();
        if delta > 0 && used.1 + delta.unsigned_abs() > max_bytes {
            return Err(EDQUOT);
        }
        used.1 = used.1.saturating_add_signed(delta);
        Ok(())
    }
}

/// A key, as Linux's `struct key`.
pub(crate) struct Key {
    serial: i32,
    kind: Kind,
    description: Vec<u8>,
    /// Whether it counts against its owner's quota (`KEY_FLAG_IN_QUOTA`).
    in_quota: bool,
    /// One of a user's keyrings (`KEY_FLAG_UID_KEYRING`).
    uid_keyring: bool,
    quotas: Arc<Quotas>,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    uid: u32,
    gid: u32,
    perm: u32,
    /// What the key charges its owner's byte quota.
    quotalen: u64,
    /// The payload's size: a keyring's is four bytes a link.
    datalen: u64,
    /// When it expires, in seconds of the time of day; `None` for never.
    expiry: Option<i64>,
    revoked: bool,
    invalidated: bool,
    /// A negative key's error (`key->state`).
    negative: Option<Errno>,
    payload: Vec<u8>,
    /// A keyring's links, at most one for each type and description.
    links: Vec<Arc<Key>>,
    /// A keyring that refuses every link (`restrict_link_reject`).
    restricted: bool,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.serial)
    }
}

impl Drop for Key {
    /// `key_put` of the last reference: the quota goes back to the owner.
    fn drop(&mut self) {
        if self.in_quota {
            let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
            self.quotas.release(state.uid, state.quotalen);
        }
    }
}

impl Key {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn same_index(&self, kind: Kind, description: &[u8]) -> bool {
        self.kind == kind && self.description == description
    }
    /// `key_payload_reserve`: the payload becomes `datalen` bytes, the
    /// difference charged to the owner (`EDQUOT`).
    fn reserve(&self, state: &mut State, datalen: u64) -> Result<(), Errno> {
        let delta = datalen as i64 - state.datalen as i64;
        if delta != 0 && self.in_quota {
            self.quotas.adjust(state.uid, delta)?;
            state.quotalen = state.quotalen.saturating_add_signed(delta);
        }
        state.datalen = datalen;
        Ok(())
    }
}

impl State {
    /// `key_validate`.
    fn validate(&self, now: i64) -> Result<(), Errno> {
        if self.invalidated {
            return Err(ENOKEY);
        }
        if self.revoked {
            return Err(EKEYREVOKED);
        }
        if self.expiry.is_some_and(|expiry| now >= expiry) {
            return Err(EKEYEXPIRED);
        }
        Ok(())
    }
    /// `wait_for_key_construction`: no construction is ever under way, so
    /// a negative key's error, or [`Self::validate`].
    fn constructed(&self, now: i64) -> Result<(), Errno> {
        if let Some(error) = self.negative {
            return Err(error);
        }
        self.validate(now)
    }
    /// The bits of the mask that `cred` gets, possessing the key or not
    /// (`key_task_permission`).
    fn granted(&self, cred: &Credentials, possessed: bool) -> u32 {
        let mut granted = if self.uid == cred.fsuid {
            self.perm >> 16
        } else if self.gid != INVALID
            && self.perm & group(ALL) != 0
            && (self.gid == cred.fsgid || cred.groups.contains(&self.gid))
        {
            self.perm >> 8
        } else {
            self.perm
        };
        if possessed {
            granted |= self.perm >> 24;
        }
        granted
    }
    fn permits(&self, cred: &Credentials, possessed: bool, need: u32) -> bool {
        self.granted(cred, possessed) & need == need
    }
}

/// A thread's keyrings and its `request_key` default, which its
/// credentials hold in Linux.
#[derive(Clone, Debug, Default)]
pub(crate) struct Keyrings {
    thread: Option<Arc<Key>>,
    process: Option<Arc<Key>>,
    session: Option<Arc<Key>>,
    /// `jit_keyring` (`KEY_REQKEY_DEFL_*`).
    default: i32,
}

impl Keyrings {
    /// What a new process gets: its parent's session keyring and default,
    /// no thread or process keyring.
    pub(crate) fn for_process(&self) -> Self {
        Self {
            session: self.session.clone(),
            default: self.default,
            ..Self::default()
        }
    }
    /// What exec leaves (`prepare_exec_creds`): the session keyring and
    /// the default.
    pub(crate) fn after_exec(&self) -> Self {
        self.for_process()
    }
    /// Whether a thread made from one with these keyrings needs a thread
    /// keyring of its own.
    pub(crate) fn has_thread_keyring(&self) -> bool {
        self.thread.is_some()
    }
}

/// A user namespace's keyrings: its register of users' keyrings, its
/// register of persistent keyrings, and the keyrings that may be joined
/// by name.
struct Space {
    namespace: Weak<crate::namespaces::Namespace>,
    names: Vec<Weak<Key>>,
    register: Option<Arc<Key>>,
    persistent: Option<Arc<Key>>,
}

#[derive(Default)]
struct Registry {
    serials: BTreeMap<i32, Weak<Key>>,
    /// The last random number drawn, and the last serial number given,
    /// which a host whose random bytes repeat counts on from, so that a
    /// dead key's number is not given again.
    drawn: i32,
    last: i32,
    spaces: Vec<Space>,
}

/// The machine's keys.
#[derive(Default)]
pub(crate) struct Keys {
    quotas: Arc<Quotas>,
    registry: Mutex<Registry>,
    /// Held while a link is made, as Linux's `keyring_serialise_link_lock`:
    /// the cycle check and the link it allows are one step.
    linking: Mutex<()>,
}

/// How a new key counts against its owner's quota.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Quota {
    /// Charged, and refused past the quota (`KEY_ALLOC_IN_QUOTA`).
    In,
    /// Charged even past it (`KEY_ALLOC_QUOTA_OVERRUN`).
    Overrun,
    /// Not charged (`KEY_ALLOC_NOT_IN_QUOTA`).
    Not,
}

/// What a lookup needs of the key (`enum key_need_perm`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Perm(u32),
    Unlink,
    Defer,
}

/// The conditions of a search (`struct keyring_search_context`).
struct Search<'a> {
    cred: &'a Credentials,
    kind: Kind,
    description: &'a [u8],
    /// Match this key, rather than the description.
    target: Option<&'a Arc<Key>>,
    /// Skip revoked, expired and negative keys, noting why.
    state_check: bool,
    skip_expired: bool,
    check_perm: bool,
    recurse: bool,
    /// `ELOOP` on going too deep, rather than skipping.
    too_deep: bool,
    now: i64,
}

enum Step {
    Found(Arc<Key>),
    Skipped,
    Next,
}

enum Flow {
    Found(Arc<Key>),
    Stop,
    Continue,
}

/// A key found, and whether the thread possesses it (`key_ref_t`).
type KeyRef = (Arc<Key>, bool);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Keys {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        lock(&self.registry)
    }

    /// `key_lookup`: the live key with this serial.
    fn by_serial(&self, serial: i32) -> Result<Arc<Key>, Errno> {
        self.registry()
            .serials
            .get(&serial)
            .and_then(Weak::upgrade)
            .ok_or(ENOKEY)
    }

    /// `key_alloc`: a new key, charged to `uid` as `quota` says, with a
    /// random serial number.
    #[allow(clippy::too_many_arguments)]
    fn alloc(
        &self,
        host: &dyn Host,
        kind: Kind,
        description: &[u8],
        (uid, gid, perm): (u32, u32, u32),
        quota: Quota,
        uid_keyring: bool,
    ) -> Result<Arc<Key>, Errno> {
        if description.is_empty() {
            return Err(Errno::EINVAL);
        }
        // `logon_vet_description`: a logon key's description is a
        // `service:` prefix and the rest.
        if kind == Kind::Logon && description.iter().position(|&b| b == b':').unwrap_or(0) == 0 {
            return Err(Errno::EINVAL);
        }
        if description.len() >= MAX_DESCRIPTION {
            return Err(Errno::EINVAL);
        }
        let quotalen = description.len() as u64 + 1;
        if quota != Quota::Not {
            self.quotas.charge(uid, quotalen, quota == Quota::Overrun)?;
        }
        let mut registry = self.registry();
        registry.serials.retain(|_, key| key.strong_count() > 0);
        // `key_alloc_serial`: a random number of at least 3, then the
        // next free one after it. A host whose random bytes do not change
        // (the test hosts) counts on from the last number instead.
        let mut bytes = [0; 4];
        let _ = host.random_bytes(&mut bytes);
        let drawn = (u32::from_le_bytes(bytes) >> 1) as i32;
        let repeated = std::mem::replace(&mut registry.drawn, drawn) == drawn;
        let mut serial = if drawn < 3 || repeated {
            registry.last.checked_add(1).unwrap_or(3).max(3)
        } else {
            drawn
        };
        while registry.serials.contains_key(&serial) {
            serial = serial.checked_add(1).unwrap_or(3);
        }
        registry.last = serial;
        let key = Arc::new(Key {
            serial,
            kind,
            description: description.to_vec(),
            in_quota: quota != Quota::Not,
            uid_keyring,
            quotas: Arc::clone(&self.quotas),
            state: Mutex::new(State {
                uid,
                gid,
                perm,
                quotalen,
                datalen: 0,
                expiry: None,
                revoked: false,
                invalidated: false,
                negative: None,
                payload: Vec::new(),
                links: Vec::new(),
                restricted: false,
            }),
        });
        registry.serials.insert(serial, Arc::downgrade(&key));
        Ok(key)
    }

    /// The keyrings of user namespace `namespace`, made when first asked
    /// for.
    fn space<R>(
        &self,
        namespace: &Arc<crate::namespaces::Namespace>,
        f: impl FnOnce(&mut Space) -> R,
    ) -> R {
        let mut registry = self.registry();
        registry
            .spaces
            .retain(|space| space.namespace.strong_count() > 0);
        let at = match registry
            .spaces
            .iter()
            .position(|space| std::ptr::eq(space.namespace.as_ptr(), Arc::as_ptr(namespace)))
        {
            Some(at) => at,
            None => {
                registry.spaces.push(Space {
                    namespace: Arc::downgrade(namespace),
                    names: Vec::new(),
                    register: None,
                    persistent: None,
                });
                registry.spaces.len() - 1
            }
        };
        f(&mut registry.spaces[at])
    }

    /// `keyring_alloc`: a new keyring, instantiated, published by name in
    /// the user namespace of `cred` unless its name starts with a dot, and
    /// linked into `dest`.
    #[allow(clippy::too_many_arguments)]
    fn keyring(
        &self,
        host: &dyn Host,
        cred: &Credentials,
        description: &[u8],
        owner: (u32, u32, u32),
        quota: Quota,
        uid_keyring: bool,
        dest: Option<&Arc<Key>>,
    ) -> Result<Arc<Key>, Errno> {
        let keyring = self.alloc(host, Kind::Keyring, description, owner, quota, uid_keyring)?;
        if let Some(dest) = dest {
            self.link_new(dest, &keyring)?;
        }
        self.publish(cred, &keyring);
        Ok(keyring)
    }

    /// `keyring_publish_name`.
    fn publish(&self, cred: &Credentials, keyring: &Arc<Key>) {
        if keyring.description.first() != Some(&b'.') {
            self.space(&cred.user.0, |space| {
                space.names.retain(|name| name.strong_count() > 0);
                space.names.push(Arc::downgrade(keyring));
            });
        }
    }

    /// `find_keyring_by_name`: the oldest keyring of this name in the
    /// thread's user namespace that it may search, whose owner the
    /// namespace maps and that is not revoked.
    fn by_name(&self, cred: &Credentials, name: &[u8]) -> Option<Arc<Key>> {
        let names: Vec<Arc<Key>> = self.space(&cred.user.0, |space| {
            space.names.iter().filter_map(Weak::upgrade).collect()
        });
        names.into_iter().find(|keyring| {
            let state = keyring.lock();
            cred.user.id_of(Ids::User, state.uid).is_some()
                && !state.revoked
                && keyring.description == name
                && state.permits(cred, false, SEARCH)
        })
    }

    /// The keys whose links the garbage collector would have taken away by
    /// `now`: invalidated ones, and those expired `kernel.keys.gc_delay`
    /// ago (`keyring_gc`). The links of a revoked or invalidated keyring
    /// stay, and so does what a link charged its keyring's owner, as
    /// `keyring_gc` calls no `key_payload_reserve`.
    fn collect(&self, now: i64) {
        let keyrings: Vec<Arc<Key>> = self
            .registry()
            .serials
            .values()
            .filter_map(Weak::upgrade)
            .filter(|key| key.kind == Kind::Keyring)
            .collect();
        let dead = |key: &Arc<Key>| {
            let state = key.lock();
            state.invalidated || state.expiry.is_some_and(|expiry| expiry + GC_DELAY <= now)
        };
        for keyring in keyrings {
            let links = {
                let state = keyring.lock();
                if state.revoked || state.invalidated {
                    continue;
                }
                state.links.clone()
            };
            // Judged without the keyring's lock, which is never held while
            // a key it links is locked.
            let gone: Vec<Arc<Key>> = links.into_iter().filter(dead).collect();
            if !gone.is_empty() {
                let mut state = keyring.lock();
                let removed: Vec<Arc<Key>> = {
                    let (removed, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut state.links)
                        .into_iter()
                        .partition(|key| gone.iter().any(|g| Arc::ptr_eq(g, key)));
                    state.links = kept;
                    removed
                };
                drop(state);
                drop(removed);
            }
        }
    }

    /// The step of a search at one key (`keyring_search_iterator`).
    fn step(
        key: &Arc<Key>,
        possessed: bool,
        s: &Search<'_>,
        result: &mut Result<KeyRef, Errno>,
    ) -> Step {
        if key.kind != s.kind {
            return Step::Next;
        }
        let state = key.lock();
        if s.state_check {
            if state.invalidated || state.revoked {
                *result = Err(EKEYREVOKED);
                return Step::Skipped;
            }
            if state.expiry.is_some_and(|expiry| s.now >= expiry) {
                if !s.skip_expired {
                    *result = Err(EKEYEXPIRED);
                }
                return Step::Skipped;
            }
        }
        let matches = match s.target {
            Some(target) => Arc::ptr_eq(key, target),
            None => key.description == s.description,
        };
        if !matches {
            return Step::Next;
        }
        if s.check_perm && !state.permits(s.cred, possessed, SEARCH) {
            *result = Err(Errno::EACCES);
            return Step::Skipped;
        }
        if s.state_check
            && let Some(error) = state.negative
        {
            *result = Err(error);
            return Step::Skipped;
        }
        Step::Found(Arc::clone(key))
    }

    /// One keyring of a search and those below it, `depth` below where it
    /// started (`search_nested_keyrings`).
    fn visit(
        keyring: &Arc<Key>,
        depth: usize,
        possessed: bool,
        s: &Search<'_>,
        result: &mut Result<KeyRef, Errno>,
    ) -> Flow {
        let links = {
            let state = keyring.lock();
            if state.revoked || state.invalidated {
                return Flow::Continue;
            }
            state.links.clone()
        };
        if let Some(key) = links
            .iter()
            .find(|key| key.same_index(s.kind, s.description))
            && let Step::Found(key) = Self::step(key, possessed, s, result)
        {
            return Flow::Found(key);
        }
        if !s.recurse {
            return Flow::Continue;
        }
        for child in links.iter().filter(|key| key.kind == Kind::Keyring) {
            if depth >= MAX_DEPTH {
                if s.too_deep {
                    *result = Err(ELOOP);
                    return Flow::Stop;
                }
                return Flow::Continue;
            }
            if s.check_perm && !child.lock().permits(s.cred, possessed, SEARCH) {
                continue;
            }
            match Self::visit(child, depth + 1, possessed, s, result) {
                Flow::Continue => {}
                flow => return flow,
            }
        }
        Flow::Continue
    }

    /// `keyring_search_rcu`: the key `s` asks for in `keyring` and the
    /// keyrings below it; `EAGAIN` when there is none.
    fn search(keyring: &KeyRef, s: &Search<'_>) -> Result<KeyRef, Errno> {
        let (top, possessed) = (&keyring.0, keyring.1);
        if top.kind != Kind::Keyring {
            return Err(Errno::ENOTDIR);
        }
        if s.check_perm && !top.lock().permits(s.cred, possessed, SEARCH) {
            return Err(Errno::EACCES);
        }
        let mut result = Err(Errno::EAGAIN);
        if top.same_index(s.kind, s.description) {
            match Self::step(top, possessed, s, &mut result) {
                Step::Found(key) => return Ok((key, possessed)),
                Step::Skipped => return result,
                Step::Next => {}
            }
        }
        match Self::visit(top, 0, possessed, s, &mut result) {
            Flow::Found(key) => Ok((key, possessed)),
            _ => result,
        }
    }

    /// `keyring_search`: a key of `kind` described as `description` in
    /// `keyring`, by the thread's credentials, skipping revoked and
    /// expired keys.
    fn keyring_search(
        keyring: &KeyRef,
        cred: &Credentials,
        kind: Kind,
        description: &[u8],
        recurse: bool,
        now: i64,
    ) -> Result<KeyRef, Errno> {
        if description.len() >= MAX_DESCRIPTION {
            return Err(Errno::EINVAL);
        }
        Self::search(
            keyring,
            &Search {
                cred,
                kind,
                description,
                target: None,
                state_check: true,
                skip_expired: false,
                check_perm: true,
                recurse,
                too_deep: false,
                now,
            },
        )
    }

    /// `keyring_detect_cycle`: whether linking `key` into `keyring` would
    /// make a cycle (`EDEADLK`) or a tree too deep to search (`ELOOP`).
    fn detect_cycle(keyring: &Arc<Key>, key: &Arc<Key>, cred: &Credentials) -> Result<(), Errno> {
        let found = Self::search(
            &(Arc::clone(key), false),
            &Search {
                cred,
                kind: keyring.kind,
                description: &keyring.description,
                target: Some(keyring),
                state_check: false,
                skip_expired: false,
                check_perm: false,
                recurse: true,
                too_deep: true,
                now: 0,
            },
        );
        match found {
            Ok(_) => Err(EDEADLK),
            Err(Errno::EAGAIN) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// `__key_link_begin`: where `key` goes in `keyring`, charging the
    /// owner for a new link, and refused in a revoked keyring.
    fn link_begin(
        keyring: &Key,
        state: &mut State,
        kind: Kind,
        description: &[u8],
    ) -> Result<Option<usize>, Errno> {
        if keyring.kind != Kind::Keyring {
            return Err(Errno::ENOTDIR);
        }
        if state.revoked {
            return Err(EKEYREVOKED);
        }
        let at = state
            .links
            .iter()
            .position(|link| link.same_index(kind, description));
        if at.is_none() {
            let datalen = state.datalen + LINK_BYTES;
            keyring.reserve(state, datalen)?;
        }
        Ok(at)
    }

    /// `__key_link_end` of a link not made.
    fn link_cancel(keyring: &Key, state: &mut State, at: Option<usize>) {
        if at.is_none() {
            let datalen = state.datalen.saturating_sub(LINK_BYTES);
            let _ = keyring.reserve(state, datalen);
        }
    }

    /// `__key_link`: the link, replacing the one to a key of the same type
    /// and description. Returns the key it replaced, to drop once no lock
    /// is held.
    fn link_commit(state: &mut State, key: &Arc<Key>) -> Option<Arc<Key>> {
        match state
            .links
            .iter()
            .position(|link| link.same_index(key.kind, &key.description))
        {
            Some(at) => Some(std::mem::replace(&mut state.links[at], Arc::clone(key))),
            None => {
                state.links.push(Arc::clone(key));
                None
            }
        }
    }

    /// The link of a key just made into `keyring`, without the restriction
    /// and cycle checks that a new key needs none of.
    fn link_new(&self, keyring: &Arc<Key>, key: &Arc<Key>) -> Result<(), Errno> {
        let mut state = keyring.lock();
        Self::link_begin(keyring, &mut state, key.kind, &key.description)?;
        let old = Self::link_commit(&mut state, key);
        drop(state);
        drop(old);
        Ok(())
    }

    /// `key_link`.
    fn link(&self, keyring: &Arc<Key>, key: &Arc<Key>, cred: &Credentials) -> Result<(), Errno> {
        let _linking = lock(&self.linking);
        let mut state = keyring.lock();
        let at = Self::link_begin(keyring, &mut state, key.kind, &key.description)?;
        let checked = if state.restricted {
            Err(Errno::EPERM)
        } else if key.kind == Kind::Keyring {
            drop(state);
            let checked = Self::detect_cycle(keyring, key, cred);
            state = keyring.lock();
            checked
        } else {
            Ok(())
        };
        if let Err(error) = checked {
            Self::link_cancel(keyring, &mut state, at);
            return Err(error);
        }
        let old = Self::link_commit(&mut state, key);
        drop(state);
        drop(old);
        Ok(())
    }

    /// `key_unlink`.
    fn unlink(keyring: &Arc<Key>, key: &Arc<Key>) -> Result<(), Errno> {
        if keyring.kind != Kind::Keyring {
            return Err(Errno::ENOTDIR);
        }
        let mut state = keyring.lock();
        let at = state
            .links
            .iter()
            .position(|link| Arc::ptr_eq(link, key))
            .ok_or(Errno::ENOENT)?;
        let old = state.links.remove(at);
        let datalen = state.datalen.saturating_sub(LINK_BYTES);
        let _ = keyring.reserve(&mut state, datalen);
        drop(state);
        drop(old);
        Ok(())
    }
}

/// The calling thread's keyrings.
fn keyrings(c: &Context<'_>) -> Keyrings {
    c.group.keyrings(c.tid)
}

fn set_keyrings(c: &Context<'_>, keyrings: Keyrings) {
    c.group.set_keyrings(c.tid, keyrings);
}

fn now(c: &Context<'_>) -> i64 {
    c.host
        .clock(ClockId::Realtime)
        .map_or(0, |nanos| (nanos / 1_000_000_000) as i64)
}

fn keys<'a>(c: &Context<'a>) -> &'a Keys {
    &c.processes.keys
}

/// `look_up_user_keyrings`: the thread's user keyring and user session
/// keyring, made in its user namespace's register when first asked for.
fn user_keyrings(c: &Context<'_>) -> Result<(Arc<Key>, Arc<Key>), Errno> {
    let keys = keys(c);
    let cred = &c.process.credentials;
    let namespace = Arc::clone(&cred.user.0);
    let register = match keys.space(&namespace, |space| space.register.clone()) {
        Some(register) => register,
        None => {
            let register = keys.keyring(
                c.host,
                cred,
                b".user_reg",
                (
                    namespace.users.owner(),
                    INVALID,
                    possessor(WRITE | SEARCH) | user(VIEW | READ),
                ),
                Quota::In,
                false,
                None,
            )?;
            keys.space(&namespace, |space| {
                Arc::clone(space.register.get_or_insert(register))
            })
        }
    };
    let uid = cred.user.id_of(Ids::User, cred.uid).unwrap_or(INVALID);
    let perm = possessor(ALL & !SETATTR) | user(ALL);
    let now = now(c);
    let register = (register, true);
    let name = format!("_uid.{uid}").into_bytes();
    let uid_keyring = match Keys::keyring_search(&register, cred, Kind::Keyring, &name, false, now)
    {
        Ok((keyring, _)) => keyring,
        Err(Errno::EAGAIN) => keys.keyring(
            c.host,
            cred,
            &name,
            (cred.uid, INVALID, perm),
            Quota::In,
            true,
            Some(&register.0),
        )?,
        Err(error) => return Err(error),
    };
    let name = format!("_uid_ses.{uid}").into_bytes();
    let session = match Keys::keyring_search(&register, cred, Kind::Keyring, &name, false, now) {
        Ok((keyring, _)) => keyring,
        Err(Errno::EAGAIN) => {
            let session = keys.keyring(
                c.host,
                cred,
                &name,
                (cred.uid, INVALID, perm),
                Quota::In,
                true,
                None,
            )?;
            keys.link(&session, &uid_keyring, cred)?;
            keys.link(&register.0, &session, cred)?;
            session
        }
        Err(error) => return Err(error),
    };
    Ok((uid_keyring, session))
}

/// `get_user_session_keyring_rcu`: the thread's user session keyring if
/// it has been made.
fn existing_user_session(c: &Context<'_>) -> Option<Arc<Key>> {
    let cred = &c.process.credentials;
    let register = keys(c).space(&cred.user.0, |space| space.register.clone())?;
    let uid = cred.user.id_of(Ids::User, cred.uid).unwrap_or(INVALID);
    let name = format!("_uid_ses.{uid}").into_bytes();
    Keys::keyring_search(&(register, true), cred, Kind::Keyring, &name, false, now(c))
        .ok()
        .map(|(keyring, _)| keyring)
}

/// `search_process_keyrings_rcu`: `s` in the thread's keyrings, in turn,
/// and in its user session keyring when it has no session keyring. A
/// thread here never holds a request's authority, so that is all.
fn search_process(c: &Context<'_>, s: &Search<'_>) -> Result<KeyRef, Errno> {
    let rings = keyrings(c);
    let mut found: Option<Errno> = None;
    let mut error = Errno::EAGAIN;
    let mut first = true;
    let session = rings.session.clone().or_else(|| existing_user_session(c));
    for keyring in [rings.thread.clone(), rings.process.clone(), session].into_iter() {
        let is_first = std::mem::replace(&mut first, false);
        let Some(keyring) = keyring else {
            continue;
        };
        match Keys::search(&(keyring, true), s) {
            Ok(key) => return Ok(key),
            Err(Errno::EAGAIN) if !is_first && found.is_some() => {}
            Err(e @ (Errno::EAGAIN | ENOKEY)) => found = Some(e),
            Err(e) => error = e,
        }
    }
    Err(found.unwrap_or(error))
}

/// A new thread or process keyring of the thread (`_tid`, `_pid`).
fn private_keyring(c: &Context<'_>, name: &[u8]) -> Result<Arc<Key>, Errno> {
    let cred = &c.process.credentials;
    keys(c).keyring(
        c.host,
        cred,
        name,
        (cred.uid, cred.gid, possessor(ALL) | user(VIEW)),
        Quota::Overrun,
        false,
        None,
    )
}

/// A thread keyring for a new thread of a thread that has one
/// (`copy_creds`).
pub(crate) fn thread_keyring_for(
    processes: &crate::processes::Processes,
    host: &dyn Host,
    cred: &Credentials,
) -> Option<Arc<Key>> {
    processes
        .keys
        .keyring(
            host,
            cred,
            b"_tid",
            (cred.uid, cred.gid, possessor(ALL) | user(VIEW)),
            Quota::Overrun,
            false,
            None,
        )
        .ok()
}

impl Keyrings {
    pub(crate) fn with_thread_keyring(mut self, keyring: Option<Arc<Key>>) -> Self {
        self.thread = keyring;
        self
    }
    /// `key_fsuid_changed` and `key_fsgid_changed`: the thread keyring
    /// follows the thread's filesystem IDs.
    pub(crate) fn follow_ids(&self, old: &Credentials, new: &Credentials) {
        if let Some(thread) = &self.thread {
            let mut state = thread.lock();
            if old.fsuid != new.fsuid {
                state.uid = new.fsuid;
            }
            if old.fsgid != new.fsgid {
                state.gid = new.fsgid;
            }
        }
    }
}

/// `install_session_keyring_to_cred` of a new anonymous session keyring
/// (`_ses`), charged even past the quota when the thread has none.
fn new_session(c: &Context<'_>, rings: &Keyrings) -> Result<Arc<Key>, Errno> {
    let cred = &c.process.credentials;
    keys(c).keyring(
        c.host,
        cred,
        b"_ses",
        (cred.uid, cred.gid, possessor(ALL) | user(VIEW | READ)),
        if rings.session.is_some() {
            Quota::In
        } else {
            Quota::Overrun
        },
        false,
        None,
    )
}

/// `join_session_keyring`: a new anonymous session keyring, or the
/// keyring of this name (made if there is none); 0 when it is the session
/// keyring already.
fn join_session(c: &Context<'_>, name: Option<&[u8]>) -> Result<u64, Errno> {
    let mut rings = keyrings(c);
    let Some(name) = name else {
        let keyring = new_session(c, &rings)?;
        let serial = keyring.serial;
        rings.session = Some(keyring);
        set_keyrings(c, rings);
        return Ok(serial as u64);
    };
    let cred = &c.process.credentials;
    let keys = keys(c);
    let _linking = lock(&keys.linking);
    let keyring = match keys.by_name(cred, name) {
        Some(keyring) => {
            if rings
                .session
                .as_ref()
                .is_some_and(|session| Arc::ptr_eq(session, &keyring))
            {
                return Ok(0);
            }
            keyring
        }
        None => keys.keyring(
            c.host,
            cred,
            name,
            (
                cred.uid,
                cred.gid,
                possessor(ALL) | user(VIEW | READ | LINK),
            ),
            Quota::In,
            false,
            None,
        )?,
    };
    let serial = keyring.serial;
    rings.session = Some(keyring);
    set_keyrings(c, rings);
    Ok(serial as u64)
}

/// `lookup_user_key`: the key `id` names, a special ID making the
/// keyring it names when `create`, checked for `need`; a key under
/// construction is never seen, so `partial` only spares negative keys.
fn lookup(
    c: &Context<'_>,
    id: i32,
    create: bool,
    partial: bool,
    need: Need,
) -> Result<KeyRef, Errno> {
    let (key, possessed) = loop {
        let mut rings = keyrings(c);
        match id {
            THREAD_KEYRING | PROCESS_KEYRING => {
                let (slot, name) = if id == THREAD_KEYRING {
                    (&mut rings.thread, &b"_tid"[..])
                } else {
                    (&mut rings.process, &b"_pid"[..])
                };
                if let Some(keyring) = slot {
                    break (Arc::clone(keyring), true);
                }
                if !create {
                    return Err(ENOKEY);
                }
                *slot = Some(private_keyring(c, name)?);
                set_keyrings(c, rings);
            }
            SESSION_KEYRING => match &rings.session {
                Some(session) if !(session.uid_keyring && create) => {
                    break (Arc::clone(session), true);
                }
                Some(_) => {
                    join_session(c, None)?;
                }
                None => {
                    let (_, user_session) = user_keyrings(c)?;
                    if create {
                        join_session(c, None)?;
                    } else {
                        rings.session = Some(user_session);
                        set_keyrings(c, rings);
                    }
                }
            },
            USER_KEYRING => break (user_keyrings(c)?.0, true),
            USER_SESSION_KEYRING => break (user_keyrings(c)?.1, true),
            GROUP_KEYRING => return Err(Errno::EINVAL),
            REQKEY_AUTH_KEY | REQUESTOR_KEYRING | BPF_KEYRING | DM_VERITY_KEYRING
            | FS_VERITY_KEYRING => return Err(ENOKEY),
            id if id < 1 => return Err(Errno::EINVAL),
            id => {
                let key = keys(c).by_serial(id)?;
                let possessed = search_process(
                    c,
                    &Search {
                        cred: &c.process.credentials,
                        kind: key.kind,
                        description: &key.description,
                        target: Some(&key),
                        state_check: false,
                        skip_expired: false,
                        check_perm: true,
                        recurse: true,
                        too_deep: false,
                        now: now(c),
                    },
                )
                .is_ok();
                break (key, possessed);
            }
        }
    };
    let state = key.lock();
    if need != Need::Unlink {
        let now = now(c);
        if !partial {
            if let Err(error) = state.constructed(now)
                && need != Need::Defer
            {
                return Err(error);
            }
        } else if need != Need::Defer {
            state.validate(now)?;
        }
    }
    if let Need::Perm(bits) = need
        && !state.permits(&c.process.credentials, possessed, bits)
    {
        return Err(Errno::EACCES);
    }
    drop(state);
    Ok((key, possessed))
}

/// `key_get_instantiation_authkey`: the authority to instantiate key
/// `id`, which no thread here has: the error searching for it gives.
fn authority(c: &Context<'_>, id: i32) -> Errno {
    let description = format!("{:x}", id as u32).into_bytes();
    let found = search_process(
        c,
        &Search {
            cred: &c.process.credentials,
            kind: Kind::Authority,
            description: &description,
            target: None,
            state_check: true,
            skip_expired: false,
            check_perm: true,
            recurse: true,
            too_deep: false,
            now: now(c),
        },
    );
    match found {
        Err(Errno::EAGAIN) | Ok(_) => ENOKEY,
        Err(error) => error,
    }
}

/// `strndup_user`: a string of fewer than `limit` bytes (`EINVAL`), its
/// bytes readable (`EFAULT`).
fn string(c: &Context<'_>, at: u64, limit: usize) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::new();
    for offset in 0..limit as u64 {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(at.wrapping_add(offset)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(Errno::EINVAL)
}

/// `key_get_type_from_user`: a type name of 1 to 31 bytes, not one of
/// the kernel's own (`.`, `EPERM`).
fn type_name(c: &Context<'_>, at: u64) -> Result<Vec<u8>, Errno> {
    let mut name = Vec::new();
    for offset in 0..32u64 {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(at.wrapping_add(offset)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            break;
        }
        name.push(byte[0]);
    }
    if name.is_empty() || name.len() >= 32 {
        return Err(Errno::EINVAL);
    }
    if name[0] == b'.' {
        return Err(Errno::EPERM);
    }
    Ok(name)
}

fn payload(c: &Context<'_>, at: u64, len: u64) -> Result<Vec<u8>, Errno> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0; len as usize];
    c.mem
        .read(GuestAddr(at), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(bytes)
}

fn outcome(result: Result<u64, Errno>) -> Outcome {
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

/// The default permissions of a key a thread makes (`KEY_PERM_UNDEF` in
/// `key_create_or_update` and `construct_alloc_key`).
fn default_perm(kind: Kind) -> u32 {
    let mut perm = possessor(VIEW | SEARCH | LINK | SETATTR) | user(VIEW);
    if kind.readable() {
        perm |= possessor(READ);
    }
    if kind == Kind::Keyring || kind.updatable() {
        perm |= possessor(WRITE);
    }
    perm
}

/// `user_preparse`: a payload of 1 to 32767 bytes.
fn check_user_payload(payload: &[u8]) -> Result<(), Errno> {
    if payload.is_empty() || payload.len() > MAX_USER_PAYLOAD {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// `user_update`: the new payload, charged, and the key no longer
/// negative nor expiring.
fn update_payload(key: &Key, state: &mut State, payload: Vec<u8>) -> Result<(), Errno> {
    key.reserve(state, payload.len() as u64)?;
    state.expiry = None;
    state.payload = payload;
    state.negative = None;
    Ok(())
}

/// `add_key(type, description, payload, plen, keyring)`, as Linux's
/// `key_create_or_update`: a key of an updatable type already in the
/// keyring is updated in place.
pub(crate) fn sys_add_key(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(add_key(c, a))
}

fn add_key(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    keys(c).collect(now(c));
    if a[3] > MAX_PAYLOAD {
        return Err(Errno::EINVAL);
    }
    let name = type_name(c, a[0])?;
    let description = if a[1] == 0 {
        None
    } else {
        let description = string(c, a[1], MAX_DESCRIPTION)?;
        if description.is_empty() {
            None
        } else if description[0] == b'.' && name.starts_with(b"keyring") {
            return Err(Errno::EPERM);
        } else {
            Some(description)
        }
    };
    let payload = payload(c, a[2], a[3])?;
    let keyring = lookup(c, a[4] as i32, true, false, Need::Perm(WRITE))?;
    let kind = match Kind::named(&name) {
        Some(kind) if kind != Kind::Authority => kind,
        _ => return Err(Errno::ENODEV),
    };
    if keyring.0.kind != Kind::Keyring {
        return Err(Errno::ENOTDIR);
    }
    match kind {
        Kind::Keyring if !payload.is_empty() => return Err(Errno::EINVAL),
        Kind::User | Kind::Logon => check_user_payload(&payload)?,
        _ => {}
    }
    let Some(description) = description else {
        return Err(Errno::EINVAL);
    };
    let keys = keys(c);
    let cred = &c.process.credentials;
    let _linking = lock(&keys.linking);
    let mut ring = keyring.0.lock();
    let at = Keys::link_begin(&keyring.0, &mut ring, kind, &description)?;
    let fail = |ring: &mut State, error: Errno| {
        Keys::link_cancel(&keyring.0, ring, at);
        Err(error)
    };
    if ring.restricted {
        return fail(&mut ring, Errno::EPERM);
    }
    if !ring.permits(cred, keyring.1, WRITE) {
        return fail(&mut ring, Errno::EACCES);
    }
    if kind.updatable()
        && let Some(existing) = at.map(|at| Arc::clone(&ring.links[at]))
    {
        let usable = {
            let state = existing.lock();
            !state.revoked && !state.invalidated
        };
        if usable {
            Keys::link_cancel(&keyring.0, &mut ring, at);
            drop(ring);
            let mut state = existing.lock();
            if !state.permits(cred, keyring.1, WRITE) {
                return Err(Errno::EACCES);
            }
            update_payload(&existing, &mut state, payload)?;
            return Ok(existing.serial as u64);
        }
    }
    drop(ring);
    let key = keys.alloc(
        c.host,
        kind,
        &description,
        (cred.fsuid, cred.fsgid, default_perm(kind)),
        Quota::In,
        false,
    );
    let mut ring = keyring.0.lock();
    let key = match key {
        Ok(key) => key,
        Err(error) => return fail(&mut ring, error),
    };
    if kind != Kind::Keyring {
        let mut state = key.lock();
        if let Err(error) = key.reserve(&mut state, payload.len() as u64) {
            drop(state);
            return fail(&mut ring, error);
        }
        state.payload = payload;
    }
    let old = Keys::link_commit(&mut ring, &key);
    drop(ring);
    drop(old);
    if kind == Kind::Keyring {
        keys.publish(cred, &key);
    }
    Ok(key.serial as u64)
}

/// `request_key(type, description, callout_info, dest_keyring)`.
pub(crate) fn sys_request_key(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(request_key(c, a))
}

fn request_key(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    keys(c).collect(now(c));
    let name = type_name(c, a[0])?;
    let description = string(c, a[1], MAX_DESCRIPTION)?;
    let callout = if a[2] == 0 {
        None
    } else {
        Some(string(c, a[2], PAGE_SIZE as usize)?)
    };
    let dest = if a[3] as i32 != 0 {
        Some(lookup(c, a[3] as i32, true, false, Need::Perm(WRITE))?)
    } else {
        None
    };
    let kind = Kind::named(&name).ok_or(ENOKEY)?;
    if description.len() >= MAX_DESCRIPTION {
        return Err(Errno::EINVAL);
    }
    let cred = &c.process.credentials;
    let now = now(c);
    let search = Search {
        cred,
        kind,
        description: &description,
        target: None,
        state_check: true,
        skip_expired: true,
        check_perm: true,
        recurse: true,
        too_deep: false,
        now,
    };
    match search_process(c, &search) {
        Ok((key, possessed)) => {
            if let Some((dest, _)) = &dest {
                if !key.lock().permits(cred, possessed, LINK) {
                    return Err(Errno::EACCES);
                }
                keys(c).link(dest, &key, cred)?;
            }
            key.lock().constructed(now)?;
            Ok(key.serial as u64)
        }
        Err(Errno::EAGAIN) if callout.is_some() => {
            construct(c, kind, &description, dest.map(|d| d.0))
        }
        Err(Errno::EAGAIN) => Err(ENOKEY),
        Err(error) => Err(error),
    }
}

/// `construct_key_and_link` with no `/sbin/request-key` to run: the key
/// is made in the destination keyring, the upcall fails with `ENOENT`,
/// and the key is negated for [`NEGATIVE_TIMEOUT`] seconds.
fn construct(
    c: &Context<'_>,
    kind: Kind,
    description: &[u8],
    dest: Option<Arc<Key>>,
) -> Result<u64, Errno> {
    if kind == Kind::Keyring {
        return Err(Errno::EPERM);
    }
    let cred = &c.process.credentials;
    let rings = keyrings(c);
    let dest = match dest {
        Some(dest) => dest,
        None => {
            // `construct_get_dest_keyring`: the default names where the
            // search for a keyring starts.
            let chain = match rings.default {
                0 | 7 | 1 => [
                    rings.thread.clone(),
                    rings.process.clone(),
                    rings.session.clone(),
                ],
                2 => [None, rings.process.clone(), rings.session.clone()],
                3 => [None, None, rings.session.clone()],
                4 | 5 => [None, None, None],
                _ => return Err(Errno::EINVAL),
            };
            let dest = match chain.into_iter().flatten().next() {
                Some(keyring) => keyring,
                None if rings.default == 4 => user_keyrings(c)?.0,
                None => user_keyrings(c)?.1,
            };
            if !dest.lock().permits(cred, true, WRITE) {
                return Err(Errno::EACCES);
            }
            dest
        }
    };
    let keys = keys(c);
    let key = keys.alloc(
        c.host,
        kind,
        description,
        (cred.fsuid, cred.fsgid, default_perm(kind)),
        Quota::In,
        false,
    )?;
    keys.link_new(&dest, &key)?;
    // `call_sbin_request_key` looks up the user's keyrings before the
    // upcall it cannot make; either failure negates the key.
    let failed = user_keyrings(c).err().unwrap_or(Errno::ENOENT);
    let mut state = key.lock();
    state.negative = Some(ENOKEY);
    state.expiry = Some(now(c) + NEGATIVE_TIMEOUT);
    Err(failed)
}

/// `keyctl(option, arg2, arg3, arg4, arg5)`.
pub(crate) fn sys_keyctl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    outcome(keyctl(c, a))
}

fn serial(value: u64) -> i32 {
    value as i32
}

fn keyctl(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    keys(c).collect(now(c));
    match a[0] as i32 {
        0 => Ok(
            lookup(c, serial(a[1]), a[2] as i32 != 0, false, Need::Perm(SEARCH))?
                .0
                .serial as u64,
        ),
        1 => {
            let name = if a[1] == 0 {
                None
            } else {
                let name = string(c, a[1], MAX_DESCRIPTION)?;
                if name.first() == Some(&b'.') {
                    return Err(Errno::EPERM);
                }
                Some(name)
            };
            join_session(c, name.as_deref())
        }
        2 => update(c, serial(a[1]), a[2], a[3]),
        3 => revoke(c, serial(a[1])),
        4 => chown(c, serial(a[1]), a[2] as u32, a[3] as u32),
        5 => setperm(c, serial(a[1]), a[2] as u32),
        6 => describe(c, serial(a[1]), a[2], u64::from(a[3] as u32)),
        7 => clear(c, serial(a[1])),
        8 => {
            let keyring = lookup(c, serial(a[2]), true, false, Need::Perm(WRITE))?;
            let key = lookup(c, serial(a[1]), true, false, Need::Perm(LINK))?;
            keys(c).link(&keyring.0, &key.0, &c.process.credentials)?;
            Ok(0)
        }
        9 => {
            let keyring = lookup(c, serial(a[2]), false, false, Need::Perm(WRITE))?;
            let key = lookup(c, serial(a[1]), false, true, Need::Unlink)?;
            Keys::unlink(&keyring.0, &key.0)?;
            Ok(0)
        }
        10 => search(c, a),
        11 => read(c, serial(a[1]), a[2], a[3]),
        12 => instantiate(c, a[2], a[3], false),
        13 => reject(c, ENOKEY.0 as u32),
        14 => set_default(c, a[1] as i32),
        15 => set_timeout(c, serial(a[1]), a[2] as u32),
        16 => assume_authority(c, serial(a[1])),
        17 => security(c, serial(a[1]), a[2], a[3]),
        18 => session_to_parent(c),
        19 => reject(c, a[3] as u32),
        20 => instantiate(c, a[2], u64::from(a[3] as u32), true),
        21 => invalidate(c, serial(a[1])),
        22 => persistent(c, a[1] as u32, serial(a[2])),
        24 if a[2] != 0 => Err(Errno::EINVAL),
        29 => restrict(c, serial(a[1]), a[2], a[3]),
        30 => move_key(c, a),
        31 => capabilities(c, a[1], a[2]),
        _ => Err(Errno::EOPNOTSUPP),
    }
}

/// `keyctl_update_key`.
fn update(c: &Context<'_>, id: i32, at: u64, len: u64) -> Result<u64, Errno> {
    if len > PAGE_SIZE {
        return Err(Errno::EINVAL);
    }
    let payload = payload(c, at, len)?;
    let (key, possessed) = lookup(c, id, false, false, Need::Perm(WRITE))?;
    let mut state = key.lock();
    if !state.permits(&c.process.credentials, possessed, WRITE) {
        return Err(Errno::EACCES);
    }
    if !key.kind.updatable() {
        return Err(Errno::EOPNOTSUPP);
    }
    check_user_payload(&payload)?;
    update_payload(&key, &mut state, payload)?;
    Ok(0)
}

/// `keyctl_revoke_key`: by write permission or else setattr.
fn revoke(c: &Context<'_>, id: i32) -> Result<u64, Errno> {
    let (key, _) = match lookup(c, id, false, false, Need::Perm(WRITE)) {
        Err(Errno::EACCES) => lookup(c, id, false, false, Need::Perm(SETATTR))?,
        found => found?,
    };
    let mut state = key.lock();
    if !state.revoked {
        state.revoked = true;
        match key.kind {
            Kind::Keyring => {
                let links = std::mem::take(&mut state.links);
                let _ = key.reserve(&mut state, 0);
                drop(state);
                drop(links);
            }
            _ => {
                let _ = key.reserve(&mut state, 0);
                state.payload = Vec::new();
            }
        }
    }
    Ok(0)
}

/// `keyctl_chown_key`: a new owner, or a group the thread is not in,
/// needs CAP_SYS_ADMIN, and moves the quota.
fn chown(c: &Context<'_>, id: i32, owner: u32, group_id: u32) -> Result<u64, Errno> {
    let cred = &c.process.credentials;
    let new_uid = cred.user.kernel_of(Ids::User, owner);
    let new_gid = cred.user.kernel_of(Ids::Group, group_id);
    if (owner != INVALID && new_uid.is_none()) || (group_id != INVALID && new_gid.is_none()) {
        return Err(Errno::EINVAL);
    }
    if owner == INVALID && group_id == INVALID {
        return Ok(0);
    }
    let (key, _) = lookup(c, id, true, true, Need::Perm(SETATTR))?;
    let mut state = key.lock();
    let changes_owner = new_uid.is_some_and(|uid| uid != state.uid);
    let foreign_group = new_gid
        .is_some_and(|gid| gid != state.gid && gid != cred.fsgid && !cred.groups.contains(&gid));
    if (changes_owner || foreign_group) && !cred.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EACCES);
    }
    if let Some(uid) = new_uid.filter(|&uid| uid != state.uid) {
        if key.in_quota {
            key.quotas.transfer(state.uid, uid, state.quotalen)?;
        }
        state.uid = uid;
    }
    if let Some(gid) = new_gid {
        state.gid = gid;
    }
    Ok(0)
}

/// `keyctl_setperm_key`: the owner's or CAP_SYS_ADMIN's.
fn setperm(c: &Context<'_>, id: i32, perm: u32) -> Result<u64, Errno> {
    if perm & !(possessor(ALL) | user(ALL) | group(ALL) | ALL) != 0 {
        return Err(Errno::EINVAL);
    }
    let (key, _) = lookup(c, id, true, true, Need::Perm(SETATTR))?;
    let cred = &c.process.credentials;
    let mut state = key.lock();
    if state.uid != cred.fsuid && !cred.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EACCES);
    }
    state.perm = perm;
    Ok(0)
}

/// `keyctl_describe_key`: `type;uid;gid;perm;description`, copied only
/// when it all fits, and its length with the NUL.
fn describe(c: &Context<'_>, id: i32, buffer: u64, len: u64) -> Result<u64, Errno> {
    let (key, _) = lookup(c, id, false, true, Need::Perm(VIEW))?;
    let state = key.lock();
    let mut text = key.kind.name().to_vec();
    text.extend_from_slice(
        format!(
            ";{};{};{:08x};",
            c.shown_uid(state.uid) as i32,
            c.shown_gid(state.gid) as i32,
            state.perm
        )
        .as_bytes(),
    );
    drop(state);
    text.extend_from_slice(&key.description);
    text.push(0);
    if buffer != 0 && len >= text.len() as u64 {
        c.mem
            .write(GuestAddr(buffer), &text)
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(text.len() as u64)
}

/// `keyctl_keyring_clear`.
fn clear(c: &Context<'_>, id: i32) -> Result<u64, Errno> {
    let (keyring, _) = lookup(c, id, true, false, Need::Perm(WRITE))?;
    if keyring.kind != Kind::Keyring {
        return Err(Errno::ENOTDIR);
    }
    let mut state = keyring.lock();
    let links = std::mem::take(&mut state.links);
    let _ = keyring.reserve(&mut state, 0);
    drop(state);
    drop(links);
    Ok(0)
}

/// `keyctl_keyring_search`: from a keyring the thread may search, linked
/// into `dest` when it may link it.
fn search(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let name = type_name(c, a[2])?;
    let description = string(c, a[3], MAX_DESCRIPTION)?;
    let keyring = lookup(c, serial(a[1]), false, false, Need::Perm(SEARCH))?;
    let dest = if serial(a[4]) != 0 {
        Some(lookup(c, serial(a[4]), true, false, Need::Perm(WRITE))?)
    } else {
        None
    };
    let kind = Kind::named(&name).ok_or(ENOKEY)?;
    let cred = &c.process.credentials;
    let (key, possessed) =
        match Keys::keyring_search(&keyring, cred, kind, &description, true, now(c)) {
            Err(Errno::EAGAIN) => return Err(ENOKEY),
            found => found?,
        };
    if let Some((dest, _)) = dest {
        if !key.lock().permits(cred, possessed, LINK) {
            return Err(Errno::EACCES);
        }
        keys(c).link(&dest, &key, cred)?;
    }
    Ok(key.serial as u64)
}

/// `keyctl_read_key`: by read permission or possession; the payload is
/// copied only when it fits, and its length is returned.
fn read(c: &Context<'_>, id: i32, buffer: u64, len: u64) -> Result<u64, Errno> {
    let (key, possessed) = lookup(c, id, false, false, Need::Defer).map_err(|_| ENOKEY)?;
    let state = key.lock();
    if let Some(error) = state.negative {
        return Err(error);
    }
    if !state.permits(&c.process.credentials, possessed, READ) && !possessed {
        return Err(Errno::EACCES);
    }
    state.validate(now(c))?;
    if !key.kind.readable() {
        return Err(Errno::EOPNOTSUPP);
    }
    let data: Vec<u8> = match key.kind {
        Kind::Keyring => {
            // `keyring_read` refuses a buffer that is not of whole serial
            // numbers, but only one `keyctl_read_key` passes it: one of at
            // most a page.
            if buffer != 0 && len != 0 && len <= PAGE_SIZE && !len.is_multiple_of(4) {
                return Err(Errno::EINVAL);
            }
            state
                .links
                .iter()
                .flat_map(|link| link.serial.to_le_bytes())
                .collect()
        }
        _ => state.payload.clone(),
    };
    drop(state);
    let size = data.len() as u64;
    if buffer != 0 && len != 0 && size != 0 && size <= len {
        c.mem
            .write(GuestAddr(buffer), &data)
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(size)
}

/// `KEYCTL_INSTANTIATE` and `KEYCTL_INSTANTIATE_IOV`: the payload is
/// checked, then the authority the thread never has (`EPERM`).
fn instantiate(c: &Context<'_>, at: u64, len: u64, vector: bool) -> Result<u64, Errno> {
    let len = if vector {
        let count = if at == 0 { 0 } else { len };
        crate::files::iovecs_checked(c.mem, at, count, |_, _| Ok(()))?
            .iter()
            .map(|&(_, length)| length as u64)
            .sum()
    } else if at != 0 && len != 0 {
        let cut = len.min(crate::files::MAX_RW_COUNT as u64);
        crate::sockets::access_ok_u64(at, cut)?;
        cut
    } else {
        0
    };
    if len > MAX_PAYLOAD {
        return Err(Errno::EINVAL);
    }
    Err(Errno::EPERM)
}

/// `keyctl_reject_key` (and `keyctl_negate_key`): an error code a thread
/// may give, then the authority it never has.
fn reject(_c: &Context<'_>, error: u32) -> Result<u64, Errno> {
    if error == 0 || error >= 4095 || matches!(error, 512 | 513 | 514 | 516) {
        return Err(Errno::EINVAL);
    }
    Err(Errno::EPERM)
}

/// `keyctl_set_reqkey_keyring`: the old default, after making the thread
/// or process keyring that a new one names.
fn set_default(c: &Context<'_>, default: i32) -> Result<u64, Errno> {
    let mut rings = keyrings(c);
    let old = rings.default;
    match default {
        -1 => return Ok(old as u64),
        1 => {
            if rings.thread.is_none() {
                rings.thread = Some(private_keyring(c, b"_tid")?);
            }
        }
        2 => {
            if rings.process.is_none() {
                rings.process = Some(private_keyring(c, b"_pid")?);
            }
        }
        0 | 3 | 4 | 5 | 7 => {}
        _ => return Err(Errno::EINVAL),
    }
    rings.default = default;
    set_keyrings(c, rings);
    Ok(old as u64)
}

/// `keyctl_set_timeout`: 0 for none.
fn set_timeout(c: &Context<'_>, id: i32, timeout: u32) -> Result<u64, Errno> {
    let (key, _) = lookup(c, id, true, true, Need::Perm(SETATTR))?;
    key.lock().expiry = (timeout > 0).then(|| now(c) + i64::from(timeout));
    Ok(0)
}

/// `keyctl_assume_authority`: giving up the authority the thread does not
/// have, or the error looking for the one it asks for gives.
fn assume_authority(c: &Context<'_>, id: i32) -> Result<u64, Errno> {
    match id {
        id if id < 0 => Err(Errno::EINVAL),
        0 => Ok(0),
        id => Err(authority(c, id)),
    }
}

/// `keyctl_get_security`: no module labels keys, so an empty string.
fn security(c: &Context<'_>, id: i32, buffer: u64, len: u64) -> Result<u64, Errno> {
    match lookup(c, id, false, true, Need::Perm(VIEW)) {
        Ok(_) => {}
        Err(Errno::EACCES) => return Err(authority(c, id)),
        Err(error) => return Err(error),
    }
    if buffer != 0 && len > 0 {
        c.mem
            .write(GuestAddr(buffer), &[0])
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(1)
}

/// `keyctl_session_to_parent`: the thread's session keyring becomes its
/// parent's, which must be single-threaded, not init, and have the same
/// IDs. The parent here takes it at once rather than as it next returns
/// to user space, which no system call it may be in can tell apart.
fn session_to_parent(c: &Context<'_>) -> Result<u64, Errno> {
    let (session, _) = lookup(c, SESSION_KEYRING, false, false, Need::Perm(LINK))?;
    let parent = c.processes.parent_of(c.process.pid);
    let Some(group) = Some(parent)
        .filter(|&pid| pid > 1)
        .and_then(|pid| c.processes.group_of(pid))
    else {
        return Err(Errno::EPERM);
    };
    let Some((tid, parent_rings)) = group.only_keyrings() else {
        return Err(Errno::EPERM);
    };
    if parent_rings
        .session
        .as_ref()
        .is_some_and(|own| Arc::ptr_eq(own, &session))
    {
        return Ok(0);
    }
    let mine = &c.process.credentials;
    let theirs = group.task_ids(tid, tid);
    if [theirs.uid, theirs.euid, theirs.suid] != [mine.euid; 3]
        || [theirs.gid, theirs.egid, theirs.sgid] != [mine.egid; 3]
    {
        return Err(Errno::EPERM);
    }
    if parent_rings
        .session
        .as_ref()
        .is_some_and(|own| own.lock().uid != mine.euid)
        || session.lock().uid != mine.euid
    {
        return Err(Errno::EPERM);
    }
    group.set_keyrings(
        tid,
        Keyrings {
            session: Some(session),
            ..parent_rings
        },
    );
    Ok(0)
}

/// `keyctl_invalidate_key`: by search permission; its links go at once.
fn invalidate(c: &Context<'_>, id: i32) -> Result<u64, Errno> {
    let (key, _) = lookup(c, id, false, false, Need::Perm(SEARCH))?;
    key.lock().invalidated = true;
    keys(c).collect(now(c));
    Ok(0)
}

/// `keyctl_get_persistent`: the persistent keyring of `uid` (the caller's
/// for -1, another's with CAP_SETUID), made if there is none, linked into
/// `dest`, and kept for three days from now.
fn persistent(c: &Context<'_>, uid: u32, dest: i32) -> Result<u64, Errno> {
    let cred = &c.process.credentials;
    let namespace = Arc::clone(&cred.user.0);
    let uid = if uid == INVALID {
        cred.uid
    } else {
        let kernel = cred.user.kernel_of(Ids::User, uid).ok_or(Errno::EINVAL)?;
        if kernel != cred.uid && kernel != cred.euid && !cred.capable_in(CAP_SETUID, &namespace) {
            return Err(Errno::EPERM);
        }
        kernel
    };
    let (dest, _) = lookup(c, dest, true, false, Need::Perm(WRITE))?;
    if dest.kind != Kind::Keyring {
        return Err(Errno::ENOTDIR);
    }
    let keys = keys(c);
    let name = format!(
        "_persistent.{}",
        cred.user.id_of(Ids::User, uid).unwrap_or(INVALID)
    )
    .into_bytes();
    let register = match keys.space(&namespace, |space| space.persistent.clone()) {
        Some(register) => register,
        None => {
            let register = keys.keyring(
                c.host,
                cred,
                b".persistent_register",
                (0, 0, possessor(ALL & !SETATTR) | user(VIEW | READ)),
                Quota::Not,
                false,
                None,
            )?;
            keys.space(&namespace, |space| {
                Arc::clone(space.persistent.get_or_insert(register))
            })
        }
    };
    let existing = {
        let state = register.lock();
        state
            .links
            .iter()
            .find(|link| link.same_index(Kind::Keyring, &name))
            .filter(|link| {
                let state = link.lock();
                !state.revoked && !state.invalidated
            })
            .cloned()
    };
    let (keyring, created) = match existing {
        Some(keyring) => (keyring, false),
        None => (
            keys.keyring(
                c.host,
                cred,
                &name,
                (uid, INVALID, possessor(ALL & !SETATTR) | user(VIEW | READ)),
                Quota::Not,
                false,
                Some(&register),
            )?,
            true,
        ),
    };
    let linked = keys.link(&dest, &keyring, cred);
    if linked.is_ok() || created {
        keyring.lock().expiry = Some(now(c) + PERSISTENT_EXPIRY);
    }
    linked?;
    Ok(keyring.serial as u64)
}

/// `keyctl_restrict_keyring`: only a restriction that refuses every link
/// can be made, as no type here has restrictions of its own (`ENOENT`).
fn restrict(c: &Context<'_>, id: i32, kind: u64, restriction: u64) -> Result<u64, Errno> {
    let (keyring, _) = lookup(c, id, false, false, Need::Perm(SETATTR))?;
    let named = if kind != 0 {
        if restriction == 0 {
            return Err(Errno::EINVAL);
        }
        let name = type_name(c, kind)?;
        string(c, restriction, PAGE_SIZE as usize)?;
        Some(name)
    } else {
        if restriction != 0 {
            return Err(Errno::EINVAL);
        }
        None
    };
    if keyring.kind != Kind::Keyring {
        return Err(Errno::ENOTDIR);
    }
    if let Some(name) = named {
        Kind::named(&name).ok_or(ENOKEY)?;
        return Err(Errno::ENOENT);
    }
    let mut state = keyring.lock();
    if state.restricted {
        return Err(Errno::EEXIST);
    }
    state.restricted = true;
    Ok(0)
}

/// `keyctl_keyring_move`: the link from one keyring to another, displacing
/// a key of the same type and description unless `KEYCTL_MOVE_EXCL`.
fn move_key(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let flags = a[4] as u32;
    if flags & !1 != 0 {
        return Err(Errno::EINVAL);
    }
    let (key, _) = lookup(c, serial(a[1]), true, false, Need::Perm(LINK))?;
    let (from, _) = lookup(c, serial(a[2]), false, false, Need::Perm(WRITE))?;
    let (to, _) = lookup(c, serial(a[3]), true, false, Need::Perm(WRITE))?;
    if Arc::ptr_eq(&from, &to) {
        return Ok(0);
    }
    if from.kind != Kind::Keyring || to.kind != Kind::Keyring {
        return Err(Errno::ENOTDIR);
    }
    let keys = keys(c);
    let _linking = lock(&keys.linking);
    if !from.lock().links.iter().any(|link| Arc::ptr_eq(link, &key)) {
        return Err(Errno::ENOENT);
    }
    let mut state = to.lock();
    let at = Keys::link_begin(&to, &mut state, key.kind, &key.description)?;
    let checked = if at.is_some() && flags & 1 != 0 {
        Err(Errno::EEXIST)
    } else if state.restricted {
        Err(Errno::EPERM)
    } else if key.kind == Kind::Keyring {
        drop(state);
        let checked = Keys::detect_cycle(&to, &key, &c.process.credentials);
        state = to.lock();
        checked
    } else {
        Ok(())
    };
    if let Err(error) = checked {
        Keys::link_cancel(&to, &mut state, at);
        return Err(error);
    }
    let old = Keys::link_commit(&mut state, &key);
    drop(state);
    drop(old);
    Keys::unlink(&from, &key)?;
    Ok(0)
}

/// `keyctl_capabilities`: [`CAPABILITIES`], the rest of the buffer
/// cleared.
fn capabilities(c: &Context<'_>, buffer: u64, len: u64) -> Result<u64, Errno> {
    if len > 0 {
        let copied = len.min(CAPABILITIES.len() as u64);
        c.mem
            .write(GuestAddr(buffer), &CAPABILITIES[..copied as usize])
            .map_err(|_| Errno::EFAULT)?;
        // `clear_user` of the rest.
        let zeros = [0; PAGE_SIZE as usize];
        let mut at = copied;
        while at < len {
            let chunk = (len - at).min(PAGE_SIZE);
            c.mem
                .write(GuestAddr(buffer.wrapping_add(at)), &zeros[..chunk as usize])
                .map_err(|_| Errno::EFAULT)?;
            at += chunk;
        }
    }
    Ok(CAPABILITIES.len() as u64)
}
