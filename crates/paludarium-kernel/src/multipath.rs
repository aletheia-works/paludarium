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
/// `inet_rtm_getroute` builds one for IPv4 and an ICMP error's lookup takes
/// the one it tells of (`icmp_route_lookup`), rather than a flow alone,
/// with the flow hash that packet carries, 0 for none: its sender's
/// (`skb_set_hash_from_sk` of `sk_txhash`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flow {
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub label: u32,
    pub packet: bool,
    pub socket_hash: u32,
}

impl Flow {
    /// A flow of `proto` with no ports, as one that carries none has.
    pub(crate) fn of(proto: u8) -> Self {
        Self {
            proto,
            ..Self::default()
        }
    }
    /// A socket's flow of `proto` from the port `sport` to `dport`.
    pub(crate) fn socket(proto: u8, sport: u16, dport: u16) -> Self {
        Self {
            proto,
            sport,
            dport,
            ..Self::default()
        }
    }
    /// The flow of an answer to this one: its ports the other way round.
    pub(crate) fn reversed(self) -> Self {
        Self {
            sport: self.dport,
            dport: self.sport,
            ..self
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

/// What a hash may take of a flow: the fields `fib_multipath_hash_fields`
/// names, each address, the protocol, the flow label and each port.
#[derive(Clone, Copy, Default)]
struct Keys<A> {
    proto: u8,
    label: u32,
    sport: u16,
    dport: u16,
    src: A,
    dst: A,
}

/// Where the hash reads each key: the bytes of Linux's `struct flow_keys`
/// on x86-64 from its `basic` member on, which the hash must read alike to
/// choose as Linux does, the same as an ABI. Everything else is 0.
const AT_PROTO: usize = 2;
const AT_LABEL: usize = 4;
const AT_PORTS: usize = 28;
const AT_ADDRESSES: usize = 36;

impl<A: Copy + Default + AsRef<[u8]>> Keys<A> {
    /// Only the fields `fields` names, the others 0.
    fn only(self, fields: u32) -> Self {
        let keep = |field: u32| fields & field != 0;
        Self {
            proto: if keep(IP_PROTO) { self.proto } else { 0 },
            label: if keep(FLOWLABEL) { self.label } else { 0 },
            sport: if keep(SRC_PORT) { self.sport } else { 0 },
            dport: if keep(DST_PORT) { self.dport } else { 0 },
            src: if keep(SRC_IP) { self.src } else { A::default() },
            dst: if keep(DST_IP) { self.dst } else { A::default() },
        }
    }
    /// The keys the same way round for a flow and its answer: the lower
    /// address first, as `lower` compares them, and the lower port first,
    /// each as the machine reads its bytes in network order.
    fn either_way(mut self, lower: impl Fn(&A, &A) -> bool) -> Self {
        if lower(&self.dst, &self.src) {
            core::mem::swap(&mut self.src, &mut self.dst);
        }
        if self.dport.swap_bytes() < self.sport.swap_bytes() {
            core::mem::swap(&mut self.sport, &mut self.dport);
        }
        self
    }
    /// The bytes the hash reads, written into `out`: their length, padded
    /// to whole 8-byte words.
    fn write(self, out: &mut [u8; 72]) -> usize {
        let (src, dst) = (self.src.as_ref(), self.dst.as_ref());
        out[AT_PROTO] = self.proto;
        out[AT_LABEL..AT_LABEL + 4].copy_from_slice(&self.label.to_be_bytes());
        out[AT_PORTS..AT_PORTS + 2].copy_from_slice(&self.sport.to_be_bytes());
        out[AT_PORTS + 2..AT_PORTS + 4].copy_from_slice(&self.dport.to_be_bytes());
        let end = AT_ADDRESSES + src.len();
        out[AT_ADDRESSES..end].copy_from_slice(src);
        out[end..end + dst.len()].copy_from_slice(dst);
        (end + dst.len()).next_multiple_of(8)
    }
}

/// The outer fields a family's `policy` hashes, as ip-sysctl tells of
/// `fib_multipath_hash_policy`: layer 3 (0, and 2, which only a packet's
/// inner headers set apart), for IPv6 with its flow label and next header;
/// layer 4, the addresses, protocol and ports (1); or the outer fields
/// `fib_multipath_hash_fields` names (3).
fn hashed(policy: Policy, v6: bool) -> u32 {
    const LAYER_3: u32 = SRC_IP | DST_IP;
    const LAYER_4: u32 = LAYER_3 | IP_PROTO | SRC_PORT | DST_PORT;
    match policy.policy {
        1 => LAYER_4,
        3 => policy.fields & OUTER,
        _ if v6 => LAYER_3 | FLOWLABEL | IP_PROTO,
        _ => LAYER_3,
    }
}

impl Seed {
    /// The key of SipHash: the namespace's seed where it has one, else the
    /// machine's, in both halves of both words.
    fn key(self) -> [u64; 2] {
        let seed = u64::from(if self.user == 0 {
            self.machine
        } else {
            self.user
        });
        [seed << 32 | seed; 2]
    }
    /// The hash of the fields `fields` names of `keys`, alike for a flow and
    /// its answer and never 0; 0 where none is named.
    fn of<A: Copy + Default + AsRef<[u8]>>(
        self,
        fields: u32,
        keys: Keys<A>,
        lower: impl Fn(&A, &A) -> bool,
    ) -> u32 {
        if fields == 0 {
            return 0;
        }
        let mut bytes = [0u8; 72];
        let len = keys.only(fields).either_way(lower).write(&mut bytes);
        ((siphash(self.key(), &bytes[..len]) & 0xffff_ffff) as u32).max(1)
    }
    /// The hash that chooses an IPv4 hop for `flow` from `src` to `dst`
    /// (`fib_multipath_hash`), of the fields `policy` takes ([`hashed`]).
    /// Under policy 1 a packet that carries its socket's hash is hashed by
    /// that alone; under 3 a packet's hash of its outer headers is mixed
    /// with that of its inner ones, which none here has.
    pub(crate) fn hash4(self, policy: Policy, src: Ipv4Addr, dst: Ipv4Addr, flow: Flow) -> u32 {
        if policy.policy == 1 && flow.packet && flow.socket_hash != 0 {
            return flow.socket_hash >> 1;
        }
        let (sport, dport) = flow.ports();
        let keys = Keys {
            proto: flow.proto,
            label: 0,
            sport,
            dport,
            src: src.octets(),
            dst: dst.octets(),
        };
        let lower = |a: &[u8; 4], b: &[u8; 4]| u32::from_le_bytes(*a) < u32::from_le_bytes(*b);
        let hash = self.of(hashed(policy, false), keys, lower);
        if policy.policy == 3 && flow.packet {
            mix(hash, 0) >> 1
        } else {
            hash >> 1
        }
    }
    /// The hash that chooses an IPv6 hop for `flow` from `src` to `dst`
    /// (`rt6_multipath_hash`), of the fields `policy` takes ([`hashed`]).
    pub(crate) fn hash6(self, policy: Policy, src: Ipv6Addr, dst: Ipv6Addr, flow: Flow) -> u32 {
        let keys = Keys {
            proto: flow.proto,
            label: flow.label,
            sport: flow.sport,
            dport: flow.dport,
            src: src.octets(),
            dst: dst.octets(),
        };
        self.of(hashed(policy, true), keys, |a, b| a < b) >> 1
    }
}

/// Bob Jenkins' lookup3 hash of the two words `first` and `second` with no
/// initial value: its three words start at 0xdeadbeef and the length in
/// bytes, the two added in, then its final mix, which turns each word into
/// the next by the one before it, seven times.
fn mix(first: u32, second: u32) -> u32 {
    let start = 0xdead_beef_u32.wrapping_add(8);
    let mut words = [start.wrapping_add(first), start.wrapping_add(second), start];
    for (step, turn) in [14, 11, 25, 16, 4, 14, 24].into_iter().enumerate() {
        let (into, by) = ((step + 2) % 3, (step + 1) % 3);
        words[into] ^= words[by];
        words[into] = words[into].wrapping_sub(words[by].rotate_left(turn));
    }
    words[2]
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
            socket_hash: 0,
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
        assert_eq!(h(policy(3, 0x40), udp(1, 2, true)), mix(0, 0) >> 1);
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

    #[test]
    fn policy_1_takes_the_hash_a_packet_carries() {
        let seed = Seed {
            machine: 5,
            user: 0,
        };
        let policy = |policy| Policy {
            policy,
            fields: FIELDS_ALL,
        };
        let (a, b) = (Ipv4Addr::new(10, 5, 0, 1), Ipv4Addr::new(10, 2, 0, 1));
        let packet = Flow {
            packet: true,
            ..Flow::socket(17, 7100, 9)
        };
        let carried = Flow {
            socket_hash: 0x8765_4321,
            ..packet
        };
        // The hash the packet carries, halved, whatever its keys.
        assert_eq!(seed.hash4(policy(1), a, b, carried), 0x8765_4321 >> 1);
        assert_ne!(
            seed.hash4(policy(1), a, b, packet),
            seed.hash4(policy(1), a, b, carried)
        );
        // A flow's lookup has no packet's hash, and the other policies
        // dissect the packet.
        let flow = Flow {
            packet: false,
            ..carried
        };
        assert_eq!(
            seed.hash4(policy(1), a, b, flow),
            seed.hash4(policy(1), a, b, Flow::socket(17, 7100, 9))
        );
        for other in [0, 2, 3] {
            assert_eq!(
                seed.hash4(policy(other), a, b, carried),
                seed.hash4(policy(other), a, b, packet)
            );
        }
    }

    #[test]
    fn an_answer_hashes_its_ports_as_the_flow_it_answers() {
        let seed = Seed {
            machine: 5,
            user: 0,
        };
        let ports = Policy {
            policy: 1,
            fields: FIELDS_DEFAULT,
        };
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 2, 0, 7));
        let flow = Flow::socket(6, 7100, 7000);
        assert_eq!(flow.reversed(), Flow::socket(6, 7000, 7100));
        assert_eq!(
            seed.hash4(ports, a, b, flow),
            seed.hash4(ports, b, a, flow.reversed())
        );
        assert_ne!(
            seed.hash4(ports, a, b, flow),
            seed.hash4(ports, a, b, Flow::socket(6, 7101, 7000))
        );
        let (a, b): (Ipv6Addr, Ipv6Addr) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8:2::7".parse().unwrap(),
        );
        assert_eq!(
            seed.hash6(ports, a, b, flow),
            seed.hash6(ports, b, a, flow.reversed())
        );
    }
    /// Every hash as it stood before the hash was rewritten in a
    /// structure of its own: the rewrite keeps each bit.
    fn pinned_hashes() -> Vec<u32> {
        let seeds = [
            Seed {
                machine: 5,
                user: 0,
            },
            Seed {
                machine: 5,
                user: 0x1234_5678,
            },
            Seed {
                machine: 0xdead_beef,
                user: 0,
            },
        ];
        let v4 = [
            (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 2, 0, 7)),
            (Ipv4Addr::new(192, 168, 9, 200), Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let v6: [(Ipv6Addr, Ipv6Addr); 2] = [
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8:2::7".parse().unwrap(),
            ),
            ("fe80::9".parse().unwrap(), "2001:db8::1".parse().unwrap()),
        ];
        let flows = [
            Flow::default(),
            Flow::socket(17, 7100, 9),
            Flow::socket(6, 40000, 80),
            Flow {
                packet: true,
                ..Flow::socket(17, 7100, 9)
            },
            Flow {
                packet: true,
                socket_hash: 0x8765_4321,
                ..Flow::socket(17, 7100, 9)
            },
            Flow {
                packet: true,
                ..Flow::socket(1, 3, 4)
            },
            Flow {
                label: 0xabcde,
                ..Flow::socket(58, 0, 0)
            },
            Flow {
                label: 0x12345,
                ..Flow::socket(6, 1, 65535)
            },
        ];
        let mut policies = vec![
            Policy {
                policy: 0,
                fields: 0,
            },
            Policy {
                policy: 1,
                fields: 0,
            },
            Policy {
                policy: 2,
                fields: 0,
            },
        ];
        for fields in [
            0, 0x40, 0x7, 0x3f, 0x10, 0x20, 0x8, 0x37, 0x3, 0x30, FIELDS_ALL,
        ] {
            policies.push(Policy { policy: 3, fields });
        }
        let mut all = Vec::new();
        for seed in seeds {
            for policy in &policies {
                for flow in flows {
                    for (a, b) in v4 {
                        all.push(seed.hash4(*policy, a, b, flow));
                    }
                    for (a, b) in v6 {
                        all.push(seed.hash6(*policy, a, b, flow));
                    }
                }
            }
        }
        all
    }

    #[test]
    fn the_hashes_keep_their_bits() {
        let all = pinned_hashes();
        let digest = all.iter().fold(0xcbf2_9ce4_8422_2325u64, |d, &h| {
            (d ^ u64::from(h)).wrapping_mul(0x0100_0000_01b3)
        });
        assert_eq!(
            (all.len(), digest),
            (1344, 5_159_730_338_909_324_338),
            "{:x?}",
            &all[..16]
        );
        let mixed: Vec<u32> = [0, 1, 0x8000_0000, 0x1234_5678, u32::MAX]
            .into_iter()
            .map(|a| mix(a, 0))
            .collect();
        assert_eq!(
            mixed,
            [
                0x58c1_84bf,
                0x5543_253f,
                0xfefd_f3e7,
                0xd134_ea9a,
                0x05e7_a47a
            ]
        );
    }
}
