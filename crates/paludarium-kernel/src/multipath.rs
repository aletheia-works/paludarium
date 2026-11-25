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

impl Seed {
    /// `flow_hash_from_keys_seed` of `keys`, with both halves of both words
    /// of the key the seed (`fib_multipath_hash_construct_key`). The keys are
    /// `struct flow_keys` from `basic` on, on x86-64: 2 bytes of a protocol
    /// (0), `ip_proto`, a byte, the flow label in network order, 8 of each
    /// VLAN (0), 4 of a key ID (0), 4 of the ports (0 under policy 0), 4 of
    /// ICMP (0), then the addresses, with the structure's padding to 8 bytes
    /// at its end (`flow_keys_hash_length`).
    fn hash(self, keys: &[u8]) -> u32 {
        let seed = u64::from(if self.user == 0 {
            self.machine
        } else {
            self.user
        });
        let word = seed << 32 | seed;
        match (siphash([word, word], keys) & 0xffff_ffff) as u32 {
            0 => 1,
            hash => hash,
        }
    }
    /// `fib_multipath_hash` of a packet from `src` to `dst`, of policy 0.
    pub(crate) fn hash4(self, src: Ipv4Addr, dst: Ipv4Addr) -> u32 {
        let (mut src, mut dst) = (src.octets(), dst.octets());
        // `__flow_hash_consistentify`: the two as the machine's words.
        if u32::from_le_bytes(dst) < u32::from_le_bytes(src) {
            core::mem::swap(&mut src, &mut dst);
        }
        let mut keys = [0; 48];
        keys[36..40].copy_from_slice(&src);
        keys[40..44].copy_from_slice(&dst);
        self.hash(&keys) >> 1
    }
    /// `rt6_multipath_hash` of a flow from `src` to `dst`, of policy 0.
    pub(crate) fn hash6(self, src: Ipv6Addr, dst: Ipv6Addr, label: u32, proto: u8) -> u32 {
        let (mut src, mut dst) = (src.octets(), dst.octets());
        if dst < src {
            core::mem::swap(&mut src, &mut dst);
        }
        let mut keys = [0; 72];
        keys[2] = proto;
        keys[4..8].copy_from_slice(&label.to_be_bytes());
        keys[36..52].copy_from_slice(&src);
        keys[52..68].copy_from_slice(&dst);
        self.hash(&keys) >> 1
    }
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
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 2, 0, 7));
        assert_eq!(of(0).hash4(a, b), of(0).hash4(b, a));
        assert_eq!(of(0).hash4(a, b), of(5).hash4(a, b));
        assert_ne!(of(0).hash4(a, b), of(6).hash4(a, b));
        let (a, b): (Ipv6Addr, Ipv6Addr) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        assert_eq!(of(9).hash6(a, b, 0, 6), of(9).hash6(b, a, 0, 6));
        assert_ne!(of(9).hash6(a, b, 0, 6), of(9).hash6(a, b, 0, 17));
        assert_ne!(of(9).hash6(a, b, 0, 6), of(9).hash6(a, b, 1, 6));
        assert!(of(9).hash6(a, b, 0, 6) < 1 << 31);
    }
}
