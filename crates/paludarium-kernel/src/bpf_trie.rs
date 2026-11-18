//! A `BPF_MAP_TYPE_LPM_TRIE`'s elements, as Linux's `kernel/bpf/lpm_trie.c`
//! keeps them: a binary trie of prefixes, whose nodes are the elements and,
//! where two prefixes part, intermediate nodes with no value. A key is the
//! prefix's length in bits (a `u32` in the machine's order) and then its
//! bytes, the most significant first (`struct bpf_lpm_trie_key_u8`).
//!
//! Its shape is Linux's, node for node, so that what depends on it is the
//! same: `GET_NEXT_KEY`'s postorder, which gives more specific prefixes
//! before less specific ones, and the bytes past a prefix's length, which
//! an element keeps from the key that last put it there and gives back as
//! its next key.
use paludarium_types::Errno;

const ENOSPC: Errno = Errno(28);
/// `BPF_NOEXIST` and `BPF_EXIST`.
const NOEXIST: u64 = 1;
const EXIST: u64 = 2;
/// `sizeof(struct bpf_lpm_trie_key_u8)` before the data: the prefix length.
pub(crate) const PREFIX: usize = 4;

/// `struct lpm_trie_node`.
struct Node<V> {
    prefixlen: u32,
    /// The element's value; none for an intermediate node
    /// (`LPM_TREE_NODE_FLAG_IM`), which is only there to tell its two
    /// children apart.
    value: Option<V>,
    data: Box<[u8]>,
    child: [Option<usize>; 2],
}

/// Where a node hangs: the root, or a node's child.
#[derive(Clone, Copy)]
enum Slot {
    Root,
    Child(usize, usize),
}

/// `struct lpm_trie`, its nodes kept by index.
pub(crate) struct Trie<V> {
    nodes: Vec<Node<V>>,
    /// Indexes of `nodes` no longer in the trie, to use again.
    free: Vec<usize>,
    root: Option<usize>,
    /// `n_entries`: the nodes with a value.
    entries: u32,
    max_entries: u32,
    /// `data_size`: the key's bytes past the prefix length.
    data_size: usize,
}

/// `extract_bit`: bit `index` of `data`, from the most significant of its
/// first byte.
fn bit(data: &[u8], index: u32) -> usize {
    let index = index as usize;
    usize::from(data[index / 8] >> (7 - index % 8) & 1)
}

/// A key's prefix length and data; one shorter than the prefix length is
/// taken as length 0 with no data, which no caller passes.
fn split(key: &[u8]) -> (u32, &[u8]) {
    match key.split_first_chunk::<PREFIX>() {
        Some((length, data)) => (u32::from_le_bytes(*length), data),
        None => (0, &[]),
    }
}

impl<V> Trie<V> {
    pub(crate) fn new(key_size: u32, max_entries: u32) -> Self {
        Trie {
            nodes: Vec::new(),
            free: Vec::new(),
            root: None,
            entries: 0,
            max_entries,
            data_size: (key_size as usize).saturating_sub(PREFIX),
        }
    }

    /// `max_prefixlen`: every bit of the data.
    fn max_prefixlen(&self) -> u32 {
        (self.data_size * 8) as u32
    }

    fn node(&self, i: usize) -> &Node<V> {
        &self.nodes[i]
    }

    fn node_mut(&mut self, i: usize) -> &mut Node<V> {
        &mut self.nodes[i]
    }

    fn at(&self, slot: Slot) -> Option<usize> {
        match slot {
            Slot::Root => self.root,
            Slot::Child(i, side) => self.node(i).child[side],
        }
    }

    fn put(&mut self, slot: Slot, node: Option<usize>) {
        match slot {
            Slot::Root => self.root = node,
            Slot::Child(i, side) => self.node_mut(i).child[side] = node,
        }
    }

    fn alloc(&mut self, node: Node<V>) -> usize {
        match self.free.pop() {
            Some(i) => {
                self.nodes[i] = node;
                i
            }
            None => {
                self.nodes.push(node);
                self.nodes.len() - 1
            }
        }
    }

    /// Node `i` out of the trie: it keeps nothing, and its index is free.
    fn release(&mut self, i: usize) {
        self.nodes[i] = Node {
            prefixlen: 0,
            value: None,
            data: Box::default(),
            child: [None, None],
        };
        self.free.push(i);
    }

    /// `longest_prefix_match`: how many of the leading bits of node `i` and
    /// of `data` agree, up to the shorter of the two prefix lengths.
    fn matching(&self, i: usize, prefixlen: u32, data: &[u8]) -> u32 {
        let node = self.node(i);
        let limit = node.prefixlen.min(prefixlen);
        let mut same = 0;
        for (a, b) in node.data.iter().zip(data).take(self.data_size) {
            let diff = a ^ b;
            same += diff.leading_zeros();
            if diff != 0 || same >= limit {
                break;
            }
        }
        same.min(limit)
    }

    /// `trie_lookup_elem`: the value of the longest prefix that holds the
    /// key, or none (a prefix length past the data's bits is none too).
    pub(crate) fn lookup(&self, key: &[u8]) -> Option<&V> {
        let (prefixlen, data) = split(key);
        if prefixlen > self.max_prefixlen() {
            return None;
        }
        let mut found = None;
        let mut next = self.root;
        while let Some(i) = next {
            let matched = self.matching(i, prefixlen, data);
            // Every bit matches: there is nothing more specific.
            if matched == self.max_prefixlen() {
                found = Some(i);
                break;
            }
            let node = self.node(i);
            if matched < node.prefixlen {
                break;
            }
            if node.value.is_some() {
                found = Some(i);
            }
            next = node.child[bit(data, node.prefixlen)];
        }
        self.node(found?).value.as_ref()
    }

    /// `trie_check_add_elem`: a new element, if `BPF_EXIST` does not want
    /// one (`ENOENT`) and there is room (`ENOSPC`).
    fn add(&mut self, flags: u64) -> Result<(), Errno> {
        if flags == EXIST {
            return Err(Errno::ENOENT);
        }
        if self.entries == self.max_entries {
            return Err(ENOSPC);
        }
        self.entries += 1;
        Ok(())
    }

    /// The path to `key`'s node, as `trie_update_elem`, `trie_delete_elem`
    /// and `trie_get_next_key` walk it: down while each node's prefix is
    /// all in the key and shorter than it. It ends with the slot of the
    /// node it stopped at (or an empty one), that node, how many of its bits
    /// match, and the nodes it went through, the last first.
    fn walk(&self, prefixlen: u32, data: &[u8]) -> (Slot, Option<usize>, u32, Vec<(Slot, usize)>) {
        let mut slot = Slot::Root;
        let mut matched = 0;
        let mut path = Vec::new();
        loop {
            let Some(i) = self.at(slot) else {
                return (slot, None, matched, path);
            };
            matched = self.matching(i, prefixlen, data);
            let node = self.node(i);
            if node.prefixlen != matched || node.prefixlen == prefixlen {
                return (slot, Some(i), matched, path);
            }
            path.push((slot, i));
            slot = Slot::Child(i, bit(data, node.prefixlen));
        }
    }

    /// `trie_update_elem`: `BPF_ANY`, `BPF_NOEXIST` or `BPF_EXIST` alone
    /// (`EINVAL` for any other flag, `BPF_F_LOCK` too), and a prefix length
    /// within the data (`EINVAL`). An element that is there is replaced
    /// with a new one, which takes its place in the trie.
    pub(crate) fn update(&mut self, key: &[u8], value: V, flags: u64) -> Result<(), Errno> {
        if flags > EXIST {
            return Err(Errno::EINVAL);
        }
        let (prefixlen, data) = split(key);
        if prefixlen > self.max_prefixlen() {
            return Err(Errno::EINVAL);
        }
        let data: Box<[u8]> = data[..self.data_size].into();
        let (slot, found, matched, _) = self.walk(prefixlen, &data);
        let Some(i) = found else {
            self.add(flags)?;
            let new = self.alloc(Node {
                prefixlen,
                value: Some(value),
                data,
                child: [None, None],
            });
            self.put(slot, Some(new));
            return Ok(());
        };
        if self.node(i).prefixlen == matched {
            // The same prefix: an element, or an intermediate node that
            // becomes one.
            if self.node(i).value.is_some() {
                if flags == NOEXIST {
                    return Err(Errno::EEXIST);
                }
            } else {
                self.add(flags)?;
            }
            let node = self.node_mut(i);
            node.value = Some(value);
            node.data = data;
            return Ok(());
        }
        self.add(flags)?;
        // The new prefix holds the node's: it goes above it.
        if matched == prefixlen {
            let side = bit(&self.node(i).data, matched);
            let mut child = [None, None];
            child[side] = Some(i);
            let new = self.alloc(Node {
                prefixlen,
                value: Some(value),
                data,
                child,
            });
            self.put(slot, Some(new));
            return Ok(());
        }
        // They part after `matched` bits: an intermediate node there has
        // both.
        let goes_right = bit(&data, matched) == 1;
        let parted = self.node(i).data.clone();
        let new = self.alloc(Node {
            prefixlen,
            value: Some(value),
            data,
            child: [None, None],
        });
        let child = if goes_right {
            [Some(i), Some(new)]
        } else {
            [Some(new), Some(i)]
        };
        let between = self.alloc(Node {
            prefixlen: matched,
            value: None,
            data: parted,
            child,
        });
        self.put(slot, Some(between));
        Ok(())
    }

    /// `trie_delete_elem`: the element of exactly `key`'s prefix (`ENOENT`
    /// for none, `EINVAL` for a prefix length past the data's bits) and its
    /// value. One with two children stays as an intermediate node; an
    /// intermediate parent left with one child goes, and the child takes
    /// its place.
    pub(crate) fn delete(&mut self, key: &[u8]) -> Result<V, Errno> {
        let (prefixlen, data) = split(key);
        if prefixlen > self.max_prefixlen() {
            return Err(Errno::EINVAL);
        }
        let (slot, found, matched, path) = self.walk(prefixlen, data);
        let Some(i) = found.filter(|&i| {
            let node = self.node(i);
            node.prefixlen == prefixlen && node.prefixlen == matched
        }) else {
            return Err(Errno::ENOENT);
        };
        // An intermediate node is no element.
        let node = self.node_mut(i);
        let Some(value) = node.value.take() else {
            return Err(Errno::ENOENT);
        };
        let child = node.child;
        self.entries -= 1;
        if child[0].is_some() && child[1].is_some() {
            return Ok(value);
        }
        if let Some(&(parent_slot, parent)) = path.last()
            && self.node(parent).value.is_none()
            && child == [None, None]
        {
            let siblings = self.node(parent).child;
            let other = if siblings[0] == Some(i) {
                siblings[1]
            } else {
                siblings[0]
            };
            self.put(parent_slot, other);
            self.release(parent);
            self.release(i);
            return Ok(value);
        }
        self.put(slot, child[0].or(child[1]));
        self.release(i);
        Ok(value)
    }

    /// The key of node `i`: its prefix length and data.
    fn key_of(&self, i: usize) -> Vec<u8> {
        let node = self.node(i);
        let mut key = node.prefixlen.to_le_bytes().to_vec();
        key.extend_from_slice(&node.data);
        key
    }

    /// The first element in postorder under node `i`: down the first child
    /// there is, the last element on the way.
    fn leftmost(&self, i: usize) -> usize {
        let mut found = i;
        let mut next = Some(i);
        while let Some(n) = next {
            let node = self.node(n);
            if node.value.is_none() {
                next = node.child[0];
            } else {
                found = n;
                next = node.child[0].or(node.child[1]);
            }
        }
        found
    }

    /// `trie_get_next_key`: the element after `key`'s in postorder, the
    /// first one for none, for a prefix length past the data's bits or for
    /// a key that is no element's; `ENOENT` past the last, and for an empty
    /// trie.
    pub(crate) fn next(&self, key: Option<&[u8]>) -> Result<Vec<u8>, Errno> {
        let root = self.root.ok_or(Errno::ENOENT)?;
        let max = self.max_prefixlen();
        if let Some((prefixlen, data)) = key.map(split).filter(|&(length, _)| length <= max) {
            let (_, found, matched, path) = self.walk(prefixlen, data);
            if let Some(i) = found
                && self.node(i).prefixlen == matched
                && self.node(i).value.is_some()
            {
                let mut node = i;
                for &(_, parent) in path.iter().rev() {
                    let parent_node = self.node(parent);
                    if parent_node.child[0] == Some(node)
                        && let Some(right) = parent_node.child[1]
                    {
                        return Ok(self.key_of(self.leftmost(right)));
                    }
                    if parent_node.value.is_some() {
                        return Ok(self.key_of(parent));
                    }
                    node = parent;
                }
                return Err(Errno::ENOENT);
            }
        }
        Ok(self.key_of(self.leftmost(root)))
    }

    /// `n_entries`.
    pub(crate) fn len(&self) -> u32 {
        self.entries
    }

    /// Every element's key and value, in postorder.
    #[cfg(test)]
    pub(crate) fn held(&self) -> Vec<(Vec<u8>, &V)> {
        let mut held = Vec::new();
        let mut key = None;
        while let Ok(next) = self.next(key.as_deref()) {
            let (prefixlen, data) = split(&next);
            let (_, found, _, _) = self.walk(prefixlen, data);
            let value = found
                .and_then(|i| self.node(i).value.as_ref())
                .expect("a next key is an element's");
            held.push((next.clone(), value));
            key = Some(next);
        }
        held
    }

    /// How many nodes there are, intermediate ones too.
    #[cfg(test)]
    fn nodes(&self) -> usize {
        self.nodes.len() - self.free.len()
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
        // A /23 is the intermediate node's prefix, which is no element.
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 23)), Some(&1));
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 15)), None);
        assert_eq!(t.lookup(&v4([10, 0, 0, 1], 32)), None);
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 33)), None);
        // Four elements and the /23 between two of them.
        assert_eq!((t.len(), t.nodes()), (4, 5));
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
    fn an_intermediate_node_becomes_an_element_with_its_prefix() {
        let mut t = trie(10);
        t.update(&v4([192, 168, 0, 0], 24), 2, 0).unwrap();
        t.update(&v4([192, 168, 1, 0], 24), 5, 0).unwrap();
        assert_eq!(t.nodes(), 3);
        let between = v4([192, 168, 0, 0], 23);
        assert_eq!(t.update(&between, 4, EXIST), Err(Errno::ENOENT));
        t.update(&between, 4, NOEXIST).unwrap();
        assert_eq!((t.len(), t.nodes()), (3, 3));
        assert_eq!(t.lookup(&v4([192, 168, 0, 0], 23)), Some(&4));
    }

    #[test]
    fn deletes_take_out_what_is_no_longer_needed() {
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
        // A leaf under an intermediate node takes it along.
        assert_eq!(t.delete(&zero), Ok(2));
        assert_eq!((t.len(), t.nodes()), (2, 2));
        assert_eq!(t.lookup(&v4([192, 168, 0, 9], 32)), Some(&1));
        // One with one child gives it its place.
        assert_eq!(t.delete(&wide), Ok(1));
        assert_eq!((t.len(), t.nodes()), (1, 1));
        assert_eq!(t.next(None), Ok(one.clone()));
        // One with two children stays, with no value.
        let mut t = trie(10);
        for (key, value) in [(&wide, 1), (&zero, 2), (&v4([192, 168, 128, 0], 24), 3)] {
            t.update(key, value, 0).unwrap();
        }
        assert_eq!(t.delete(&wide), Ok(1));
        assert_eq!((t.len(), t.nodes()), (2, 3));
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
