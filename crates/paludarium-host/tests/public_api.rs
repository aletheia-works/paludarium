//! External-crate regression for the extensible terminal contract.
use paludarium_host::{Host, StreamId, TerminalAttributes, TerminalInfo, testing::RecordingHost};

#[test]
fn attributes_constructor_preserves_every_field() {
    let chars = std::array::from_fn(|i| i as u8);
    let a = TerminalAttributes::new(1, 2, 3, 4, 5, chars);
    assert_eq!(
        (
            a.input_flags,
            a.output_flags,
            a.control_flags,
            a.local_flags,
            a.line
        ),
        (1, 2, 3, 4, 5)
    );
    assert_eq!(a.control_chars, chars);
}

#[test]
fn attributes_default_retains_linux_values() {
    let a = TerminalAttributes::default();
    assert_eq!(
        (
            a.input_flags,
            a.output_flags,
            a.control_flags,
            a.local_flags,
            a.line
        ),
        (0x500, 5, 0xbf, 0x8a3b, 0)
    );
    assert_eq!(
        a.control_chars,
        [
            3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0
        ]
    );
}

#[test]
fn terminal_constructor_preserves_dimensions_and_attributes() {
    let a = TerminalAttributes::new(10, 20, 30, 40, 50, [60; 19]);
    let t = TerminalInfo::new(a, 101, 37, 7, 9);
    assert_eq!(t.attributes, a);
    assert_eq!((t.columns, t.rows, t.x_pixels, t.y_pixels), (101, 37, 7, 9));
}

#[test]
fn default_terminal_has_zero_dimensions_and_default_attributes() {
    let t = TerminalInfo::default();
    assert_eq!(
        t,
        TerminalInfo::new(TerminalAttributes::default(), 0, 0, 0, 0)
    );
}

#[test]
fn zero_size_terminal_is_distinct_from_nonterminal() {
    let host = RecordingHost::new();
    assert_eq!(host.terminal_info(StreamId::Stdin), Ok(None));
    let t = TerminalInfo::new(TerminalAttributes::default(), 0, 0, 0, 0);
    host.set_terminal_info(StreamId::Stdin, Some(t));
    assert_eq!(host.terminal_info(StreamId::Stdin), Ok(Some(t)));
    assert_eq!(host.terminal_info(StreamId::Stdout), Ok(None));
}

#[test]
fn maximum_values_and_public_mutation_are_retained() {
    let mut t = TerminalInfo::new(
        TerminalAttributes::new(
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u8::MAX,
            [u8::MAX; 19],
        ),
        u16::MAX,
        u16::MAX,
        u16::MAX,
        u16::MAX,
    );
    assert_eq!(t.attributes.control_chars, [255; 19]);
    assert_eq!(t.attributes.input_flags, u32::MAX);
    assert_eq!(
        (t.columns, t.rows, t.x_pixels, t.y_pixels),
        (u16::MAX, u16::MAX, u16::MAX, u16::MAX)
    );
    t.columns = 0;
    t.attributes.line = 0;
    assert_eq!((t.columns, t.attributes.line), (0, 0));
}
