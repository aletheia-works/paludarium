//! The hash that chooses among a multipath route's next hops, as Linux's
//! `fib_multipath_hash_from_keys` takes it of a flow's keys.
use core::net::{Ipv4Addr, Ipv6Addr};

/// The seed of the hash (`struct sysctl_fib_multipath_hash_seed`): the
/// machine's random one, unless `net.ipv4.fib_multipath_hash_seed` of the
/// namespace is set, which keys IPv6's hash too.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Seed {
    /// `proc_fib_multipath_hash_rand_seed`, every namespace's.
    pub machine: u32,
    /// `user_seed`, 0 for none.
    pub user: u32,
}

impl Default for Seed {
    fn default() -> Self {
        static MACHINE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        let machine = *MACHINE.get_or_init(|| {
            let state = std::hash::RandomState::new();
            (core::hash::BuildHasher::hash_one(&state, 0u8) & 0xffff_ffff) as u32
        });
        Self { machine, user: 0 }
    }
}

/// A family's `fib_multipath_hash_policy` and `fib_multipath_hash_fields`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    /// 0 to 3.
    pub policy: u8,
    /// `FIB_MULTIPATH_HASH_FIELD_*`.
    pub fields: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            policy: 0,
            fields: FIELDS_DEFAULT,
        }
    }
}

/// `FIB_MULTIPATH_HASH_FIELD_SRC_IP`, `DST_IP` and `IP_PROTO`, as a
/// namespace starts with them.
pub(crate) const FIELDS_DEFAULT: u32 = 0x7;
/// `FIB_MULTIPATH_HASH_FIELD_ALL_MASK`: the outer and the inner fields.
pub(crate) const FIELDS_ALL: u32 = 0xfff;
const SRC_IP: u32 = 1;
const DST_IP: u32 = 1 << 1;
const IP_PROTO: u32 = 1 << 2;
const FLOWLABEL: u32 = 1 << 3;
const SRC_PORT: u32 = 1 << 4;
const DST_PORT: u32 = 1 << 5;
/// `FIB_MULTIPATH_HASH_FIELD_OUTER_MASK`.
const OUTER: u32 = 0x3f;

/// What a flow has besides its addresses that a hash may take: its
/// protocol and ports (`flowi4_proto`, `fl4_sport`, `fl4_dport`), and for
/// IPv6 its flow label; and whether they come in a packet (an `skb`), as
/// `inet_rtm_getroute` builds one for IPv4, rather than a flow alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flow {
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub label: u32,
    pub packet: bool,
}

impl Flow {
    /// A socket's flow of `proto`: its ports are taken as 0 here.
    pub(crate) fn of(proto: u8) -> Self {
        Self {
            proto,
            ..Self::default()
        }
    }
    /// The ports the flow dissector finds in a packet (`proto_ports_offset`
    /// over the headers `inet_rtm_getroute_build_skb` writes: TCP's and
    /// UDP's), or the flow's own.
    fn ports(self) -> (u16, u16) {
        if self.packet && !matches!(self.proto, 6 | 17) {
            (0, 0)
        } else {
            (self.sport, self.dport)
        }
    }
}

/// The keys [`Seed::hash`] takes, as `struct flow_keys` holds them.
#[derive(Clone, Copy, Default)]
struct Keys<A> {
    proto: u8,
    label: u32,
    sport: u16,
    dport: u16,
    src: A,
    dst: A,
}

impl Seed {
    /// `flow_hash_from_keys_seed` of `keys`, with both halves of both words
    /// of the key the seed (`fib_multipath_hash_construct_key`). The keys are
    /// `struct flow_keys` from `basic` on, on x86-64: 2 bytes of a protocol
    /// (0), `ip_proto`, a byte, the flow label in network order, 8 of each
    /// VLAN (0), 4 of a key ID (0), 2 of each port in network order, 4 of
    /// ICMP (0), then the addresses, with the structure's padding to 8
    /// bytes at its end (`flow_keys_hash_length`). First the addresses and
    /// then the ports go in order, each pair as the machine reads it
    /// (`__flow_hash_consistentify`).
    fn hash<const N: usize>(
        self,
        keys: Keys<[u8; N]>,
        before: impl Fn(&[u8; N], &[u8; N]) -> bool,
    ) -> u32 {
        let (mut src, mut dst) = (keys.src, keys.dst);
        if before(&dst, &src) {
            core::mem::swap(&mut src, &mut dst);
        }
        let (mut sport, mut dport) = (keys.sport.to_be_bytes(), keys.dport.to_be_bytes());
        if u16::from_le_bytes(dport) < u16::from_le_bytes(sport) {
            core::mem::swap(&mut sport, &mut dport);
        }
        let mut bytes = [0u8; 72];
        bytes[2] = keys.proto;
        bytes[4..8].copy_from_slice(&keys.label.to_be_bytes());
        bytes[28..30].copy_from_slice(&sport);
        bytes[30..32].copy_from_slice(&dport);
        bytes[36..36 + N].copy_from_slice(&src);
        bytes[36 + N..36 + 2 * N].copy_from_slice(&dst);
        let len = (36 + 2 * N).next_multiple_of(8);
        let seed = u64::from(if self.user == 0 {
            self.machine
        } else {
            self.user
        });
        let word = seed << 32 | seed;
        match (siphash([word, word], &bytes[..len]) & 0xffff_ffff) as u32 {
            0 => 1,
            hash => hash,
        }
    }
    /// `fib_multipath_hash` of `flow` from `src` to `dst`, as `policy`
    /// takes it: the addresses (0 and 2, which only a packet's inner
    /// headers set apart); those, the protocol and the ports (1); or the
    /// fields `fields` names (3), of a packet then mixed with no inner
    /// hash (`fib_multipath_custom_hash_skb`).
    pub(crate) fn hash4(self, policy: Policy, src: Ipv4Addr, dst: Ipv4Addr, flow: Flow) -> u32 {
        let before = |a: &[u8; 4], b: &[u8; 4]| u32::from_le_bytes(*a) < u32::from_le_bytes(*b);
        let (sport, dport) = flow.ports();
        let all = Keys {
            proto: flow.proto,
            label: 0,
            sport,
            dport,
            src: src.octets(),
            dst: dst.octets(),
        };
        let hash = match policy.policy {
            1 => self.hash(all, before),
            3 => {
                let outer = self.custom(policy.fields, all, before);
                if flow.packet {
                    jhash_2words(outer, 0, 0)
                } else {
                    outer
                }
            }
            _ => self.hash(
                Keys {
                    src: all.src,
                    dst: all.dst,
                    ..Keys::default()
                },
                before,
            ),
        };
        hash >> 1
    }
    /// `rt6_multipath_hash` of `flow` from `src` to `dst`, as `policy`
    /// takes it: the addresses, flow label and protocol (0 and 2); the
    /// addresses, protocol and ports (1); or the fields named (3).
    pub(crate) fn hash6(self, policy: Policy, src: Ipv6Addr, dst: Ipv6Addr, flow: Flow) -> u32 {
        let before = |a: &[u8; 16], b: &[u8; 16]| a < b;
        let all = Keys {
            proto: flow.proto,
            label: flow.label,
            sport: flow.sport,
            dport: flow.dport,
            src: src.octets(),
            dst: dst.octets(),
        };
        let hash = match policy.policy {
            1 => self.hash(Keys { label: 0, ..all }, before),
            3 => self.custom(policy.fields, all, before),
            _ => self.hash(
                Keys {
                    sport: 0,
                    dport: 0,
                    ..all
                },
                before,
            ),
        };
        hash >> 1
    }
    /// The hash of the outer fields `fields` names of `keys`, 0 for none
    /// (`fib_multipath_custom_hash_fl4`, `rt6_multipath_custom_hash_fl6`).
    fn custom<const N: usize>(
        self,
        fields: u32,
        keys: Keys<[u8; N]>,
        before: impl Fn(&[u8; N], &[u8; N]) -> bool,
    ) -> u32 {
        if fields & OUTER == 0 {
            return 0;
        }
        let has = |field| fields & field != 0;
        self.hash(
            Keys {
                proto: if has(IP_PROTO) { keys.proto } else { 0 },
                label: if has(FLOWLABEL) { keys.label } else { 0 },
                sport: if has(SRC_PORT) { keys.sport } else { 0 },
                dport: if has(DST_PORT) { keys.dport } else { 0 },
                src: if has(SRC_IP) { keys.src } else { [0; N] },
                dst: if has(DST_IP) { keys.dst } else { [0; N] },
            },
            before,
        )
    }
}

/// `jhash_2words`: Bob Jenkins' lookup3 final mix of `a`, `b` and 0.
fn jhash_2words(a: u32, b: u32, initval: u32) -> u32 {
    let init = initval.wrapping_add(0xdead_beef).wrapping_add(2 << 2);
    let (mut a, mut b, mut c) = (a.wrapping_add(init), b.wrapping_add(init), init);
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c.wrapping_sub(b.rotate_left(24))
}

/// SipHash-2-4 of `data` by `key`.
fn siphash(key: [u64; 2], data: &[u8]) -> u64 {
    let mut v = [
        key[0] ^ 0x736f_6d65_7073_6575,
        key[1] ^ 0x646f_7261_6e64_6f6d,
        key[0] ^ 0x6c79_6765_6e65_7261,
        key[1] ^ 0x7465_6462_7974_6573,
    ];
    let round = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[2] = v[2].wrapping_add(v[3]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].rotate_left(32).wrapping_add(v[3]);
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].rotate_left(32);
    };
    let (words, rest) = data.as_chunks::<8>();
    let mut last = [0; 8];
    last[..rest.len()].copy_from_slice(rest);
    last[7] = (data.len() & 0xff) as u8;
    for word in words.iter().chain([&last]) {
        let word = u64::from_le_bytes(*word);
        v[3] ^= word;
        round(&mut v);
        round(&mut v);
        v[0] ^= word;
    }
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siphash_gives_the_vectors_of_its_paper() {
        let key = [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908];
        let data: Vec<u8> = (0..15).collect();
        assert_eq!(siphash(key, &data), 0xa129_ca61_49be_45e5);
        assert_eq!(siphash(key, &[]), 0x726f_db47_dd0e_0e31);
        assert_eq!(siphash(key, &data[..8]), 0x93f5_f579_9a93_2462);
    }

    #[test]
    fn a_flow_and_its_answer_hash_alike_by_the_seed() {
        let of = |user| Seed { machine: 5, user };
        let zero = Policy::default();
        let none = Flow::default();
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 2, 0, 7));
        assert_eq!(of(0).hash4(zero, a, b, none), of(0).hash4(zero, b, a, none));
        assert_eq!(of(0).hash4(zero, a, b, none), of(5).hash4(zero, a, b, none));
        assert_ne!(of(0).hash4(zero, a, b, none), of(6).hash4(zero, a, b, none));
        let (a, b): (Ipv6Addr, Ipv6Addr) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        let flow = |label, proto| Flow {
            label,
            proto,
            ..Flow::default()
        };
        let h = |a, b, f| of(9).hash6(zero, a, b, f);
        assert_eq!(h(a, b, flow(0, 6)), h(b, a, flow(0, 6)));
        assert_ne!(h(a, b, flow(0, 6)), h(a, b, flow(0, 17)));
        assert_ne!(h(a, b, flow(0, 6)), h(a, b, flow(1, 6)));
        assert!(h(a, b, flow(0, 6)) < 1 << 31);
    }

    #[test]
    fn each_policy_takes_its_keys() {
        let seed = Seed {
            machine: 5,
            user: 0,
        };
        let policy = |policy, fields| Policy { policy, fields };
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 2, 0, 7));
        let udp = |sport, dport, packet| Flow {
            proto: 17,
            sport,
            dport,
            label: 0,
            packet,
        };
        let h = |p, f| seed.hash4(p, a, b, f);
        // 0 and 2 take the addresses alone, 1 the ports too, either way.
        assert_eq!(
            h(policy(0, 0), udp(1, 2, false)),
            h(policy(2, 0), udp(3, 4, true))
        );
        assert_eq!(
            h(policy(1, 0), udp(1, 2, false)),
            h(policy(1, 0), udp(2, 1, true))
        );
        assert_ne!(
            h(policy(1, 0), udp(1, 2, false)),
            h(policy(1, 0), udp(1, 3, false))
        );
        // ICMP's packet has no ports.
        let icmp = Flow {
            proto: 1,
            ..udp(1, 2, true)
        };
        assert_eq!(
            h(policy(1, 0), icmp),
            h(
                policy(1, 0),
                Flow {
                    proto: 1,
                    ..Flow::default()
                }
            )
        );
        // 3: the fields named; none of the outer ones hashes to 0, a
        // packet's mixed with its inner hash.
        assert_eq!(h(policy(3, 0x40), udp(1, 2, false)), 0);
        assert_eq!(
            h(policy(3, 0x40), udp(1, 2, true)),
            jhash_2words(0, 0, 0) >> 1
        );
        assert_eq!(
            h(policy(3, SRC_IP | DST_IP), udp(1, 2, false)),
            h(policy(0, 0), udp(1, 2, false))
        );
        assert_ne!(
            h(policy(3, SRC_IP | DST_IP), udp(1, 2, true)),
            h(policy(3, SRC_IP | DST_IP), udp(1, 2, false))
        );
        assert_eq!(
            h(policy(3, DST_PORT), udp(9, 2, false)),
            h(policy(3, DST_PORT), udp(8, 2, false))
        );
    }
}
