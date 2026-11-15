//! What a request leaves for its acknowledgement, as Linux's
//! `struct netlink_ext_ack`: a message, and the attribute at fault and its
//! policy, or the type of an attribute missing (`NL_SET_ERR_ATTR_MISS`).
//! None of the requests taken here sets a cookie.
//! Each request the kernel takes begins with none ([`begin`]); the checks
//! that refuse it say why as Linux's `NL_SET_ERR_MSG` and the others do,
//! and a socket with `NETLINK_EXT_ACK` has them in its `NLMSG_ERROR`, or in
//! a dump's `NLMSG_DONE`, as `netlink_ack_tlv_fill` puts them
//! ([`attributes`]).
//!
//! An attribute is named by its value, a slice of the request, whose
//! header the 4 bytes before it are; its offset is taken from the
//! request's start as the acknowledgement is made, as Linux takes the
//! distance of its pointer from the `nlmsghdr`.
use super::{Nla, attribute};
use paludarium_types::Errno;
use std::cell::RefCell;

const NLMSGERR_ATTR_MSG: u16 = 1;
const NLMSGERR_ATTR_OFFS: u16 = 2;
const NLMSGERR_ATTR_POLICY: u16 = 4;
const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;
const NL_POLICY_TYPE_ATTR_TYPE: u16 = 1;
const NL_POLICY_TYPE_ATTR_MIN_VALUE_S: u16 = 2;
const NL_POLICY_TYPE_ATTR_MAX_VALUE_S: u16 = 3;
const NL_POLICY_TYPE_ATTR_MIN_VALUE_U: u16 = 4;
const NL_POLICY_TYPE_ATTR_MAX_VALUE_U: u16 = 5;
const NL_POLICY_TYPE_ATTR_MIN_LENGTH: u16 = 6;
const NL_POLICY_TYPE_ATTR_MAX_LENGTH: u16 = 7;
const NL_POLICY_TYPE_ATTR_MASK: u16 = 12;
const NL_ATTR_TYPE_U8: u32 = 2;
const NL_ATTR_TYPE_U16: u32 = 3;
const NL_ATTR_TYPE_U32: u32 = 4;
const NL_ATTR_TYPE_S32: u32 = 8;
const NL_ATTR_TYPE_BINARY: u32 = 10;
const NL_ATTR_TYPE_STRING: u32 = 11;
const NL_ATTR_TYPE_NUL_STRING: u32 = 12;
const NL_ATTR_TYPE_NESTED: u32 = 13;

/// One request's report.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Report {
    message: Option<&'static str>,
    /// The address of the bad attribute's header.
    bad: Option<usize>,
    policy: Option<Nla>,
    /// The type of an attribute the request lacks.
    miss: Option<u16>,
}

thread_local! {
    static REPORT: RefCell<Report> = RefCell::default();
    /// The report of a check made early that Linux makes later
    /// ([`defer`]).
    static PENDING: RefCell<Report> = RefCell::default();
}

fn with(f: impl FnOnce(&mut Report)) {
    REPORT.with(|report| f(&mut report.borrow_mut()));
}
/// The address of the header of the attribute whose value is `value`.
fn header_of(value: &[u8]) -> usize {
    (value.as_ptr() as usize).wrapping_sub(4)
}
/// A new request: nothing is reported.
pub(crate) fn begin() {
    with(|report| *report = Report::default());
    PENDING.with(|pending| *pending.borrow_mut() = Report::default());
}
/// What `f` reports is kept aside, for a check made before Linux makes
/// it, whose error the request gives later, if at all ([`raise`]).
pub(crate) fn defer<T>(f: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
    let kept = take();
    let done = f();
    let deferred = take();
    REPORT.with(|report| *report.borrow_mut() = kept);
    if done.is_err() {
        PENDING.with(|pending| *pending.borrow_mut() = deferred);
    }
    done
}
/// The error of a deferred check, told of now as it was then: what it set
/// takes the place of what was set before.
pub(crate) fn raise(error: Errno) -> Errno {
    let pending = PENDING.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    with(|report| {
        if pending.message.is_some() {
            report.message = pending.message;
        }
        if pending.bad.is_some() {
            report.bad = pending.bad;
            report.policy = pending.policy;
        }
    });
    error
}
/// What the request reported, which is cleared.
pub(crate) fn take() -> Report {
    REPORT.with(|report| std::mem::take(&mut *report.borrow_mut()))
}
/// What `f` does with no report, as a parse Linux gives no
/// `netlink_ext_ack`: what was reported before stays.
pub(crate) fn quietly<T>(f: impl FnOnce() -> T) -> T {
    let kept = take();
    let done = f();
    REPORT.with(|report| *report.borrow_mut() = kept);
    done
}
/// `NL_SET_ERR_MSG`: `message`; the error, for a `return Err(…)`.
pub(crate) fn message(error: Errno, message: &'static str) -> Errno {
    with(|report| report.message = Some(message));
    error
}
/// `NL_SET_ERR_MSG` alone, for a warning or an error made later.
pub(crate) fn say(message: &'static str) {
    with(|report| report.message = Some(message));
}
/// `NL_SET_ERR_MSG_ATTR`: `message`, and the attribute of `value`.
pub(crate) fn at(error: Errno, value: &[u8], message: &'static str) -> Errno {
    let bad = header_of(value);
    with(|report| {
        report.message = Some(message);
        report.bad = Some(bad);
        report.policy = None;
    });
    error
}
/// `NL_SET_ERR_MSG_ATTR_POL`: [`at`], with the attribute's policy.
pub(super) fn against(error: Errno, value: &[u8], policy: Nla, message: &'static str) -> Errno {
    let bad = header_of(value);
    with(|report| {
        report.message = Some(message);
        report.bad = Some(bad);
        report.policy = Some(policy);
    });
    error
}
/// `NL_SET_ERR_ATTR_MISS`, outside a nest: attribute `kind` is missing.
pub(crate) fn missing(error: Errno, kind: u16) -> Errno {
    with(|report| report.miss = Some(kind));
    error
}
/// `NL_SET_BAD_ATTR`: the attribute of `value`, without a message.
pub(crate) fn bad(error: Errno, value: &[u8]) -> Errno {
    let bad = header_of(value);
    with(|report| {
        report.bad = Some(bad);
        report.policy = None;
    });
    error
}
impl Report {
    /// Whether the acknowledgement of `error` carries anything, as
    /// `netlink_ack_tlv_len` finds it: a message, and for an error the
    /// attribute at fault, its policy or a missing one's type. A report
    /// that does sets `NLM_F_ACK_TLVS`, though it may put nothing.
    pub(crate) fn any(&self, error: i32) -> bool {
        self.message.is_some()
            || (error != 0 && (self.bad.is_some() || self.policy.is_some() || self.miss.is_some()))
    }
}
/// The attributes the acknowledgement with `error` of a request of `len`
/// bytes, whose `payload` follows its header, carries, as
/// `netlink_ack_tlv_fill` puts them: the message; then, for an error, the
/// attribute's offset (`NLMSGERR_ATTR_OFFS`) when it lies in the request's
/// payload, its policy, and the type of an attribute missing.
pub(crate) fn attributes(report: &Report, payload: &[u8], len: u32, error: i32) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(message) = &report.message {
        let mut value = message.as_bytes().to_vec();
        value.push(0);
        attribute(&mut out, NLMSGERR_ATTR_MSG, &value);
    }
    if error == 0 {
        return out;
    }
    // `nlmsg_check_in_payload`: past the header and before the end.
    let start = (payload.as_ptr() as usize).wrapping_sub(16);
    let len = len as usize;
    let offset = |at: usize| {
        let offset = at.wrapping_sub(start);
        (16..len).contains(&offset).then_some(offset as u32)
    };
    if let Some(offset) = report.bad.and_then(offset) {
        attribute(&mut out, NLMSGERR_ATTR_OFFS, &offset.to_le_bytes());
    }
    if let Some(policy) = report.policy
        && let Some(nest) = policy_attributes(policy)
    {
        attribute(&mut out, NLMSGERR_ATTR_POLICY, &nest);
    }
    if let Some(kind) = report.miss {
        attribute(
            &mut out,
            NLMSGERR_ATTR_MISS_TYPE,
            &u32::from(kind).to_le_bytes(),
        );
    }
    out
}
/// An attribute's policy as `netlink_policy_dump_write_attr` writes it:
/// its range or most length, then its type; none for `NLA_UNSPEC`,
/// `NLA_REJECT` and `NLA_BE32`. x86-64 puts 64-bit values without padding.
fn policy_attributes(policy: Nla) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let unsigned = |out: &mut Vec<u8>, least: u64, most: u64| {
        attribute(out, NL_POLICY_TYPE_ATTR_MIN_VALUE_U, &least.to_le_bytes());
        attribute(out, NL_POLICY_TYPE_ATTR_MAX_VALUE_U, &most.to_le_bytes());
    };
    let signed = |out: &mut Vec<u8>, least: i64, most: i64| {
        attribute(out, NL_POLICY_TYPE_ATTR_MIN_VALUE_S, &least.to_le_bytes());
        attribute(out, NL_POLICY_TYPE_ATTR_MAX_VALUE_S, &most.to_le_bytes());
    };
    let length = |out: &mut Vec<u8>, most: usize| {
        if most != 0 {
            attribute(
                out,
                NL_POLICY_TYPE_ATTR_MAX_LENGTH,
                &(most as u32).to_le_bytes(),
            );
        }
    };
    let kind = match policy {
        // Linux 7.0, as CI's kernel, writes nothing for `NLA_BE32` either;
        // master gives its range with `NL_POLICY_TYPE_ATTR_BYTE_ORDER`.
        Nla::Unspec(_) | Nla::Reject | Nla::Be32 => return None,
        Nla::U8 => {
            unsigned(&mut out, 0, u8::MAX.into());
            NL_ATTR_TYPE_U8
        }
        Nla::U16 => {
            unsigned(&mut out, 0, u16::MAX.into());
            NL_ATTR_TYPE_U16
        }
        Nla::U32 => {
            unsigned(&mut out, 0, u32::MAX.into());
            NL_ATTR_TYPE_U32
        }
        Nla::U32In(least, most) => {
            unsigned(&mut out, least.into(), most.into());
            NL_ATTR_TYPE_U32
        }
        Nla::S32 => {
            signed(&mut out, i32::MIN.into(), i32::MAX.into());
            NL_ATTR_TYPE_S32
        }
        Nla::S32Min(least) => {
            signed(&mut out, least.into(), i32::MAX.into());
            NL_ATTR_TYPE_S32
        }
        Nla::String(most) => {
            length(&mut out, most);
            NL_ATTR_TYPE_STRING
        }
        Nla::NulString(most) => {
            length(&mut out, most);
            NL_ATTR_TYPE_NUL_STRING
        }
        Nla::Binary(most) => {
            length(&mut out, most);
            NL_ATTR_TYPE_BINARY
        }
        Nla::BinaryOf(size) => {
            let size = (size as u32).to_le_bytes();
            attribute(&mut out, NL_POLICY_TYPE_ATTR_MIN_LENGTH, &size);
            attribute(&mut out, NL_POLICY_TYPE_ATTR_MAX_LENGTH, &size);
            NL_ATTR_TYPE_BINARY
        }
        // `NL_POLICY_TYPE_ATTR_MASK` in place of a range.
        Nla::U32Mask(mask) => {
            attribute(
                &mut out,
                NL_POLICY_TYPE_ATTR_MASK,
                &u64::from(mask).to_le_bytes(),
            );
            NL_ATTR_TYPE_U32
        }
        Nla::Nested => NL_ATTR_TYPE_NESTED,
    };
    attribute(&mut out, NL_POLICY_TYPE_ATTR_TYPE, &kind.to_le_bytes());
    Some(out)
}
