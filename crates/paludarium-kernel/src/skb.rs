//! The sizes of x86-64 Linux 7.0's socket buffers (`struct sk_buff`), which
//! the buffers' accounting here counts as Linux's `skb->truesize` does.

/// A page.
pub(crate) const PAGE: usize = 4096;
/// `SKB_TRUESIZE`'s `struct sk_buff`, rounded to its cache line
/// (`SKB_DATA_ALIGN`).
pub(crate) const SKB: usize = 256;
/// `sizeof(struct skb_shared_info)`, at the end of every head, rounded to
/// its cache line.
pub(crate) const SHARED_INFO: usize = 320;
/// `SKB_MAX_ALLOC`: four pages less [`SHARED_INFO`], the most a head
/// takes before the bytes go in page fragments.
pub(crate) const MAX_ALLOC: usize = 4 * PAGE - SHARED_INFO;
/// `SKB_MAX_HEAD(0)`: a page less [`SHARED_INFO`].
pub(crate) const MAX_HEAD: usize = PAGE - SHARED_INFO;
/// `MAX_SKB_FRAGS` pages, the most of a buffer in page fragments.
pub(crate) const MAX_FRAGS_SIZE: usize = 17 * PAGE;
/// `SKB_SMALL_HEAD_CACHE_SIZE`, the small head cache's heads, which
/// `MAX_HEADER` sizes: 704 bytes on the CI runner's kernel, built with
/// Hyper-V's networking (640 on Docker's).
pub(crate) const SMALL_HEAD: usize = 704;

/// The `truesize` of a buffer `alloc_skb` makes for `len` bytes: the
/// `sk_buff` and its head, which holds the bytes and the `skb_shared_info`
/// in the small head cache when it fits, else in the smallest power of two
/// that does.
pub(crate) fn truesize(len: usize) -> usize {
    let head = len.next_multiple_of(64) + SHARED_INFO;
    SKB + if head <= SMALL_HEAD {
        SMALL_HEAD
    } else {
        head.next_power_of_two()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sizes_are_linux_s() {
        assert_eq!(MAX_ALLOC, 16_064);
        assert_eq!(MAX_HEAD, 3776);
        assert_eq!(MAX_FRAGS_SIZE, 69_632);
    }

    #[test]
    fn a_head_is_small_or_a_power_of_two() {
        assert_eq!(truesize(0), 960);
        assert_eq!(truesize(384), 960);
        assert_eq!(truesize(385), 1280);
        assert_eq!(truesize(704), 1280);
        assert_eq!(truesize(705), 2304);
    }
}
