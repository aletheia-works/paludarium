//! A `BPF_MAP_TYPE_LPM_TRIE`'s elements: prefixes with a value each. A key
//! is the prefix's length in bits (a `u32` in the machine's order) and then
//! its bytes, the most significant first.
//!
//! The elements are kept sorted in the order `GET_NEXT_KEY` gives them on
//! Linux: of two prefixes where one holds the other, the longer comes
//! first; otherwise the one whose first bit that differs is 0. A lookup
//! tries the prefix lengths in use, the longest the key allows first. Each
//! element keeps the bytes past its prefix from the key that last put it
//! there, which its next key gives back.
use paludarium_types::Errno;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;

const ENOSPC: Errno = Errno(28);
/// `BPF_NOEXIST` and `BPF_EXIST`.
const NOEXIST: u64 = 1;
const EXIST: u64 = 2;
/// The bytes of a key before its data: the prefix length.
pub(crate) const PREFIX: usize = 4;

/// Bit `index` of `data`, counting from the most significant of its first
/// byte.
fn bit(data: &[u8], index: u32) -> u8 {
    let index = index as usize;
    data[index / 8] >> (7 - index % 8) & 1
}

/// A key's prefix length and data; one shorter than the prefix length is
/// taken as length 0 with no data, which no caller passes.
fn split(key: &[u8]) -> (u32, &[u8]) {
    match key.split_first_chunk::<PREFIX>() {
        Some((length, data)) => (u32::from_le_bytes(*length), data),
        None => (0, &[]),
    }
}

/// A prefix: how many bits count, and `size` bytes of data with every bit
/// past those cleared, so that two keys of one prefix give equal ones.
#[derive(PartialEq, Eq)]
struct Prefix {
    length: u32,
    bits: Box<[u8]>,
}

impl Prefix {
    fn new(length: u32, data: &[u8], size: usize) -> Self {
        let mut bits = vec![0; size];
        let given = data.len().min(size);
        bits[..given].copy_from_slice(&data[..given]);
        let whole = (length / 8) as usize;
        if let Some(partial) = bits.get_mut(whole) {
            // Keep the top `length % 8` bits of the byte the prefix ends in.
            *partial &= !(0xffu8 >> (length % 8));
            bits[whole + 1..].fill(0);
        }
        Prefix {
            length,
            bits: bits.into(),
        }
    }

    /// The first bit at which the two differ, if any.
    fn parts_from(&self, other: &Prefix) -> Option<u32> {
        self.bits
            .iter()
            .zip(&other.bits)
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(at, (a, b))| at as u32 * 8 + (a ^ b).leading_zeros())
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.parts_from(other) {
            Some(at) if at < self.length.min(other.length) => {
                bit(&self.bits, at).cmp(&bit(&other.bits, at))
            }
            // One holds the other (or they are the same): the longer first.
            _ => other.length.cmp(&self.length),
        }
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// An element: the data of the key that last put it there, and its value.
struct Element<V> {
    data: Box<[u8]>,
    value: V,
}

pub(crate) struct Trie<V> {
    elements: BTreeMap<Prefix, Element<V>>,
    /// How many elements there are of each prefix length, for lookups.
    lengths: BTreeMap<u32, u32>,
    max_entries: u32,
    /// The key's bytes past the prefix length.
    data_size: usize,
}

impl<V> Trie<V> {
    pub(crate) fn new(key_size: u32, max_entries: u32) -> Self {
        Trie {
            elements: BTreeMap::new(),
            lengths: BTreeMap::new(),
            max_entries,
            data_size: (key_size as usize).saturating_sub(PREFIX),
        }
    }

    /// The longest prefix length a key can have: every bit of the data.
    fn longest(&self) -> u32 {
        (self.data_size * 8) as u32
    }

    /// `key`'s prefix, none for a length past the data's bits.
    fn prefix<'k>(&self, key: &'k [u8]) -> Option<(Prefix, &'k [u8])> {
        let (length, data) = split(key);
        (length <= self.longest()).then(|| (Prefix::new(length, data, self.data_size), data))
    }

    /// The value of the longest prefix that holds the key, or none (a
    /// prefix length past the data's bits is none too).
    pub(crate) fn lookup(&self, key: &[u8]) -> Option<&V> {
        let (length, data) = split(key);
        if length > self.longest() {
            return None;
        }
        self.lengths.range(..=length).rev().find_map(|(&used, _)| {
            let prefix = Prefix::new(used, data, self.data_size);
            self.elements.get(&prefix).map(|element| &element.value)
        })
    }

    /// `BPF_ANY`, `BPF_NOEXIST` or `BPF_EXIST` alone (`EINVAL` for any
    /// other flag, `BPF_F_LOCK` too), and a prefix length within the data
    /// (`EINVAL`). An element that is there takes the new value and data;
    /// a new one needs `BPF_EXIST` not to be asked (`ENOENT`) and room
    /// (`ENOSPC`).
    pub(crate) fn update(&mut self, key: &[u8], value: V, flags: u64) -> Result<(), Errno> {
        if flags > EXIST {
            return Err(Errno::EINVAL);
        }
        let (prefix, data) = self.prefix(key).ok_or(Errno::EINVAL)?;
        let data: Box<[u8]> = data[..self.data_size].into();
        if let Some(element) = self.elements.get_mut(&prefix) {
            if flags == NOEXIST {
                return Err(Errno::EEXIST);
            }
            *element = Element { data, value };
            return Ok(());
        }
        if flags == EXIST {
            return Err(Errno::ENOENT);
        }
        if self.len() == self.max_entries {
            return Err(ENOSPC);
        }
        *self.lengths.entry(prefix.length).or_default() += 1;
        self.elements.insert(prefix, Element { data, value });
        Ok(())
    }

    /// The element of exactly `key`'s prefix (`ENOENT` for none, `EINVAL`
    /// for a prefix length past the data's bits), taken out, and its value.
    pub(crate) fn delete(&mut self, key: &[u8]) -> Result<V, Errno> {
        let (prefix, _) = self.prefix(key).ok_or(Errno::EINVAL)?;
        let element = self.elements.remove(&prefix).ok_or(Errno::ENOENT)?;
        if let Some(count) = self.lengths.get_mut(&prefix.length) {
            *count -= 1;
            if *count == 0 {
                self.lengths.remove(&prefix.length);
            }
        }
        Ok(element.value)
    }

    fn key_of(prefix: &Prefix, element: &Element<V>) -> Vec<u8> {
        let mut key = prefix.length.to_le_bytes().to_vec();
        key.extend_from_slice(&element.data);
        key
    }

    /// The element after `key`'s, the first one for none, for a prefix
    /// length past the data's bits or for a key that is no element's;
    /// `ENOENT` past the last, and for an empty trie.
    pub(crate) fn next(&self, key: Option<&[u8]>) -> Result<Vec<u8>, Errno> {
        let from = match key.and_then(|key| self.prefix(key)) {
            Some((prefix, _)) if self.elements.contains_key(&prefix) => Bound::Excluded(prefix),
            _ => Bound::Unbounded,
        };
        self.elements
            .range((from, Bound::Unbounded))
            .next()
            .map(|(prefix, element)| Self::key_of(prefix, element))
            .ok_or(Errno::ENOENT)
    }

    /// How many elements there are.
    pub(crate) fn len(&self) -> u32 {
        self.elements.len() as u32
    }

    /// Every element's key and value, in the order of next keys.
    #[cfg(test)]
    pub(crate) fn held(&self) -> Vec<(Vec<u8>, &V)> {
        self.elements
            .iter()
            .map(|(prefix, element)| (Self::key_of(prefix, element), &element.value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 key: `a.b.c.d/length`.
    fn v4(address: [u8; 4], length: u32) -> Vec<u8> {
        let mut key = length.to_le_bytes().to_vec();
        key.extend_from_slice(&address);
        key
    }

    fn trie(max_entries: u32) -> Trie<u32> {
        Trie::new(8, max_entries)
    }

    #[test]
    fn a_lookup_finds_the_longest_prefix_that_holds_the_key() {
        let mut t = trie(10);
        t.update(&v4([192, 168, 0, 0], 16), 1, 0).unwrap();
        t.update(&v4([192, 168, 0, 0], 24), 2, 0).unwrap();
        t.update(&v4([192, 168, 128, 0], 24), 3, 0).unwrap();
        t.update(&v4([192, 168, 1, 0], 24), 5, 0).unwrap();
        assert_eq!(t.lookup(&v4([192, 168, 0, 7], 32)), Some(&2));
        assert_eq!(t.lookup(&v4([192, 168, 1, 7], 32)), Some(&5));
        assert_eq!(t.lookup(&v4([192, 168, 128, 1], 32)), Some(&3));
        assert_eq!(t.lookup(&v4([192, 168, 200, 1], 32)), Some(&1));
        // A /23 between two /24s is no element.
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 23)), Some(&1));
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 15)), None);
        assert_eq!(t.lookup(&v4([10, 0, 0, 1], 32)), None);
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 33)), None);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn next_keys_come_in_postorder_with_more_specific_prefixes_first() {
        let mut t = trie(10);
        for (address, length, value) in [
            ([192, 168, 0, 0], 16, 1),
            ([192, 168, 0, 0], 24, 2),
            ([192, 168, 128, 0], 24, 3),
            ([192, 168, 1, 0], 24, 5),
        ] {
            t.update(&v4(address, length), value, 0).unwrap();
        }
        let order: Vec<u32> = t.held().into_iter().map(|(_, &v)| v).collect();
        assert_eq!(order, [2, 5, 3, 1]);
        // The last has no next; a key that is no element's starts again.
        assert_eq!(t.next(Some(&v4([192, 168, 0, 0], 16))), Err(Errno::ENOENT));
        assert_eq!(
            t.next(Some(&v4([192, 168, 0, 0], 23))),
            Ok(v4([192, 168, 0, 0], 24))
        );
        assert_eq!(
            t.next(Some(&v4([0, 0, 0, 0], 40))),
            Ok(v4([192, 168, 0, 0], 24))
        );
        assert_eq!(trie(1).next(None), Err(Errno::ENOENT));
    }

    #[test]
    fn an_element_keeps_the_bits_past_its_prefix_from_its_last_update() {
        let mut t = trie(10);
        t.update(&v4([10, 1, 2, 3], 8), 1, 0).unwrap();
        assert_eq!(t.next(None), Ok(v4([10, 1, 2, 3], 8)));
        t.update(&v4([10, 9, 9, 9], 8), 2, 0).unwrap();
        assert_eq!(t.next(None), Ok(v4([10, 9, 9, 9], 8)));
        assert_eq!(t.lookup(&v4([10, 0, 0, 0], 8)), Some(&2));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn updates_take_the_flags_and_room_linux_gives_them() {
        let mut t = trie(2);
        let a = v4([10, 0, 0, 0], 8);
        assert_eq!(t.update(&a, 1, EXIST), Err(Errno::ENOENT));
        t.update(&a, 1, NOEXIST).unwrap();
        assert_eq!(t.update(&a, 2, NOEXIST), Err(Errno::EEXIST));
        t.update(&a, 3, EXIST).unwrap();
        assert_eq!(t.update(&a, 3, 4), Err(Errno::EINVAL));
        assert_eq!(t.update(&v4([10, 0, 0, 0], 33), 1, 0), Err(Errno::EINVAL));
        t.update(&v4([11, 0, 0, 0], 8), 4, 0).unwrap();
        assert_eq!(t.update(&v4([12, 0, 0, 0], 8), 5, 0), Err(ENOSPC));
        // A replaced element takes no more room.
        t.update(&a, 6, 0).unwrap();
        assert_eq!(t.lookup(&a), Some(&6));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn the_prefix_where_two_part_can_be_an_element_too() {
        let mut t = trie(10);
        t.update(&v4([192, 168, 0, 0], 24), 2, 0).unwrap();
        t.update(&v4([192, 168, 1, 0], 24), 5, 0).unwrap();
        let between = v4([192, 168, 0, 0], 23);
        assert_eq!(t.update(&between, 4, EXIST), Err(Errno::ENOENT));
        t.update(&between, 4, NOEXIST).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 23)), Some(&4));
    }

    #[test]
    fn a_delete_takes_out_its_exact_prefix_only() {
        let mut t = trie(10);
        let wide = v4([192, 168, 0, 0], 16);
        let zero = v4([192, 168, 0, 0], 24);
        let one = v4([192, 168, 1, 0], 24);
        for (key, value) in [(&wide, 1), (&zero, 2), (&one, 5)] {
            t.update(key, value, 0).unwrap();
        }
        assert_eq!(t.delete(&v4([192, 168, 0, 0], 23)), Err(Errno::ENOENT));
        assert_eq!(t.delete(&v4([192, 168, 0, 0], 33)), Err(Errno::EINVAL));
        assert_eq!(t.delete(&v4([192, 168, 2, 0], 24)), Err(Errno::ENOENT));
        assert_eq!(t.delete(&zero), Ok(2));
        assert_eq!(t.len(), 2);
        assert_eq!(t.lookup(&v4([192, 168, 0, 9], 32)), Some(&1));
        // What it held stays.
        assert_eq!(t.delete(&wide), Ok(1));
        assert_eq!(t.len(), 1);
        assert_eq!(t.next(None), Ok(one.clone()));
        // Deleting one that holds two others leaves them.
        let mut t = trie(10);
        for (key, value) in [(&wide, 1), (&zero, 2), (&v4([192, 168, 128, 0], 24), 3)] {
            t.update(key, value, 0).unwrap();
        }
        assert_eq!(t.delete(&wide), Ok(1));
        assert_eq!(t.len(), 2);
        assert_eq!(t.lookup(&v4([192, 168, 64, 0], 32)), None);
        assert_eq!(t.delete(&wide), Err(Errno::ENOENT));
        let order: Vec<u32> = t.held().into_iter().map(|(_, &v)| v).collect();
        assert_eq!(order, [2, 3]);
    }

    #[test]
    fn a_prefix_of_every_bit_and_one_of_none_match_as_linux_s() {
        let mut t = trie(10);
        t.update(&v4([0, 0, 0, 0], 0), 0, 0).unwrap();
        t.update(&v4([1, 2, 3, 4], 32), 32, 0).unwrap();
        assert_eq!(t.lookup(&v4([1, 2, 3, 4], 32)), Some(&32));
        assert_eq!(t.lookup(&v4([1, 2, 3, 5], 32)), Some(&0));
        assert_eq!(t.lookup(&v4([1, 2, 3, 4], 31)), Some(&0));
        let order: Vec<u32> = t.held().into_iter().map(|(_, &v)| v).collect();
        assert_eq!(order, [32, 0]);
    }

    /// A small generator, so that the runs below are the same every time.
    struct Steps(u64);
    impl Steps {
        fn next(&mut self, below: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % below
        }
    }

    /// A key of two data bytes, `length` bits of which count.
    fn short(data: u16, length: u32) -> Vec<u8> {
        let mut key = length.to_le_bytes().to_vec();
        key.extend_from_slice(&data.to_be_bytes());
        key
    }

    /// Whether the first `length` bits of `a` and `b` agree.
    fn agree(a: &[u8], b: &[u8], length: u32) -> bool {
        (0..length).all(|i| bit(a, i) == bit(b, i))
    }

    /// The elements as a list, with what the map's calls give said plainly:
    /// a lookup gives the longest prefix that holds the key; an element is
    /// a prefix length with its bits.
    #[derive(Default)]
    struct Plain {
        list: Vec<(u32, Vec<u8>, u32)>,
    }
    impl Plain {
        fn find(&self, length: u32, data: &[u8]) -> Option<usize> {
            self.list
                .iter()
                .position(|(l, d, _)| *l == length && agree(d, data, length))
        }
        fn lookup(&self, key: &[u8]) -> Option<u32> {
            let (length, data) = split(key);
            if length > 16 {
                return None;
            }
            self.list
                .iter()
                .filter(|(l, d, _)| *l <= length && agree(d, data, *l))
                .max_by_key(|(l, _, _)| *l)
                .map(|(_, _, v)| *v)
        }
        fn update(&mut self, key: &[u8], value: u32, flags: u64, room: usize) -> Result<(), Errno> {
            let (length, data) = split(key);
            if flags > EXIST || length > 16 {
                return Err(Errno::EINVAL);
            }
            match self.find(length, data) {
                Some(_) if flags == NOEXIST => Err(Errno::EEXIST),
                Some(i) => {
                    self.list[i] = (length, data.to_vec(), value);
                    Ok(())
                }
                None if flags == EXIST => Err(Errno::ENOENT),
                None if self.list.len() == room => Err(ENOSPC),
                None => {
                    self.list.push((length, data.to_vec(), value));
                    Ok(())
                }
            }
        }
        fn delete(&mut self, key: &[u8]) -> Result<u32, Errno> {
            let (length, data) = split(key);
            if length > 16 {
                return Err(Errno::EINVAL);
            }
            let i = self.find(length, data).ok_or(Errno::ENOENT)?;
            Ok(self.list.remove(i).2)
        }
    }

    /// Random updates, deletes and lookups of a 16-bit trie, each one's
    /// result as the list gives it, and the trie's order of next keys: more
    /// specific prefixes before those that hold them, and where two part,
    /// the one with a 0 there first. What it all gave before the trie was
    /// kept as a sorted map is pinned by a hash of the run, which also
    /// covers the bits past each prefix that the next keys give back.
    #[test]
    fn a_long_run_of_calls_gives_what_the_plain_list_and_the_pinned_run_give() {
        const ROOM: u32 = 24;
        let mut t: Trie<u32> = Trie::new(6, ROOM);
        let mut plain = Plain::default();
        let mut steps = Steps(0x9e37_79b9_7f4a_7c15);
        // FNV-1a over what each call gave, written out byte by byte.
        let mut run: u64 = 0xcbf2_9ce4_8422_2325;
        let mut record = |bytes: &[u8]| {
            for &b in bytes {
                run = (run ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
            }
        };
        let errno = |e: Errno| [0xff, e.0 as u8];
        for step in 0..20_000u32 {
            // Few distinct prefixes, so that the calls meet each other.
            let data = (steps.next(16) as u16) << 12 | steps.next(4) as u16;
            let length = [0, 1, 2, 3, 4, 8, 12, 15, 16, 17][steps.next(10) as usize];
            let key = short(data, length);
            match steps.next(10) {
                0..=3 => {
                    let flags = steps.next(5);
                    let got = t.update(&key, step, flags);
                    assert_eq!(
                        got,
                        plain.update(&key, step, flags, ROOM as usize),
                        "{step}"
                    );
                    record(&got.map_or_else(errno, |()| [0, 0]));
                }
                4..=5 => {
                    let got = t.delete(&key);
                    assert_eq!(got, plain.delete(&key), "{step}");
                    match got {
                        Ok(value) => record(&value.to_le_bytes()),
                        Err(e) => record(&errno(e)),
                    }
                }
                6..=8 => {
                    let got = t.lookup(&key).copied();
                    assert_eq!(got, plain.lookup(&key), "{step}");
                    record(&got.map_or([0xff; 4], u32::to_le_bytes));
                }
                _ => match t.next(Some(&key)) {
                    Ok(next) => record(&next),
                    Err(e) => record(&errno(e)),
                },
            }
            assert_eq!(t.len() as usize, plain.list.len());
            if step % 97 == 0 {
                let held = t.held();
                for pair in held.windows(2) {
                    let ((a, _), (b, _)) = (&pair[0], &pair[1]);
                    let ((la, da), (lb, db)) = (split(a), split(b));
                    let shorter = la.min(lb);
                    match (0..shorter).find(|&i| bit(da, i) != bit(db, i)) {
                        Some(i) => assert!(bit(da, i) < bit(db, i), "{step}"),
                        None => assert!(la > lb, "{step}"),
                    }
                }
                for (key, value) in held {
                    record(&key);
                    record(&value.to_le_bytes());
                }
            }
        }
        assert_eq!(run, PINNED_RUN);
    }
    const PINNED_RUN: u64 = 3_753_345_391_660_708_896;

    #[test]
    fn a_long_key_matches_past_its_first_eight_bytes() {
        let mut t: Trie<u8> = Trie::new(4 + 17, 10);
        let key = |last: u8, length: u32| {
            let mut key = length.to_le_bytes().to_vec();
            key.extend_from_slice(&[0xab; 16]);
            key.push(last);
            key
        };
        t.update(&key(0x80, 129), 1, 0).unwrap();
        t.update(&key(0x00, 136), 2, 0).unwrap();
        assert_eq!(t.lookup(&key(0xff, 136)), Some(&1));
        assert_eq!(t.lookup(&key(0x00, 136)), Some(&2));
        assert_eq!(t.lookup(&key(0x7f, 136)), None);
    }
}
