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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sizes_are_linux_s() {
        assert_eq!(MAX_ALLOC, 16_064);
        assert_eq!(MAX_HEAD, 3776);
        assert_eq!(MAX_FRAGS_SIZE, 69_632);
    }
}
