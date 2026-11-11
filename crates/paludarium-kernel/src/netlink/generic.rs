//! `NETLINK_GENERIC`, as Linux's `genetlink`, with its controller `nlctrl`
//! (`GENL_ID_CTRL`) the one family there is, as in a kernel built with no
//! other.
//!
//! A request's type names the family (`ENOENT` for another) and its
//! `genlmsghdr` the command. `CTRL_CMD_GETFAMILY` answers for `nlctrl` by
//! `CTRL_ATTR_FAMILY_ID` or `CTRL_ATTR_FAMILY_NAME`, and a dump of it lists
//! `nlctrl`; a dump of `CTRL_CMD_GETPOLICY` describes the policies of its
//! commands, or of one (`CTRL_ATTR_OP`). Any other command is `EOPNOTSUPP`.
//! The attributes are checked as `ctrl_policy_family` and
//! `ctrl_policy_policy` say, liberally for a `GETFAMILY` without a dump and
//! strictly for a dump. `nlctrl`'s one group, `notify`, is group 16, which
//! anyone may join; as no family comes or goes, it hears nothing.
use super::{
    Errno, Header, NLM_F_ACK, NLM_F_DUMP, NLM_F_ECHO, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_DONE,
    NetlinkSocket, State, align, attribute, message,
};

/// The groups a `NETLINK_GENERIC` socket has (`ngroups`): a word of them,
/// as Linux has while no family's groups reach past group 64.
pub(super) const GROUPS: u32 = 64;
/// `nlctrl`'s family ID, which is also its group's number, and its version.
const GENL_ID_CTRL: u16 = 16;
const CTRL_VERSION: u8 = 2;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_CMD_GETPOLICY: u8 = 10;
/// The commands from which on `genl_header_check` checks the header
/// (`nlctrl`'s `resv_start_op`).
const RESV_START_OP: u8 = CTRL_CMD_GETPOLICY + 1;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const CTRL_ATTR_HDRSIZE: u16 = 4;
const CTRL_ATTR_MAXATTR: u16 = 5;
const CTRL_ATTR_OPS: u16 = 6;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_POLICY: u16 = 8;
const CTRL_ATTR_OP_POLICY: u16 = 9;
const CTRL_ATTR_OP: u16 = 10;
const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;
const CTRL_ATTR_POLICY_DO: u16 = 1;
const CTRL_ATTR_POLICY_DUMP: u16 = 2;
const GENL_CMD_CAP_DO: u32 = 0x2;
const GENL_CMD_CAP_DUMP: u32 = 0x4;
const GENL_CMD_CAP_HASPOL: u32 = 0x8;
const NLA_F_NESTED: u16 = 0x8000;
const NL_POLICY_TYPE_ATTR_TYPE: u16 = 1;
const NL_POLICY_TYPE_ATTR_MIN_VALUE_U: u16 = 4;
const NL_POLICY_TYPE_ATTR_MAX_VALUE_U: u16 = 5;
const NL_POLICY_TYPE_ATTR_MAX_LENGTH: u16 = 7;
const NL_ATTR_TYPE_U16: u32 = 3;
const NL_ATTR_TYPE_U32: u32 = 4;
const NL_ATTR_TYPE_NUL_STRING: u32 = 12;
const ENOENT: Errno = Errno::ENOENT;
const EINVAL: Errno = Errno::EINVAL;
const ERANGE: Errno = Errno::ERANGE;
const EOPNOTSUPP: Errno = Errno::EOPNOTSUPP;
const EBUSY: Errno = Errno(16);

/// What an attribute of a policy is (`nla_policy`'s type, and a string's
/// longest length).
#[derive(Clone, Copy)]
enum Kind {
    U16,
    U32,
    NulString(usize),
}
/// A policy: the kind of each attribute type from 0 to its last
/// (`maxattr`), `None` for one it does not name (`NLA_UNSPEC`).
type Policy = &'static [Option<Kind>];
/// `ctrl_policy_family`, of `CTRL_CMD_GETFAMILY`.
const FAMILY_POLICY: Policy = &[None, Some(Kind::U16), Some(Kind::NulString(15))];
/// `ctrl_policy_policy`, of `CTRL_CMD_GETPOLICY`.
const POLICY_POLICY: Policy = &[
    None,
    Some(Kind::U16),
    Some(Kind::NulString(15)),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(Kind::U32),
];
/// `nlctrl`'s commands, as `genl_op_iter_next` takes them: each with the
/// policy of its `doit` and of its `dumpit`.
const COMMANDS: [(u8, Option<Policy>, Option<Policy>); 2] = [
    (CTRL_CMD_GETFAMILY, Some(FAMILY_POLICY), Some(FAMILY_POLICY)),
    (CTRL_CMD_GETPOLICY, None, Some(POLICY_POLICY)),
];

impl NetlinkSocket {
    /// One request, as `genl_rcv_msg` and `genl_family_rcv_msg`: a type
    /// that is no family is `ENOENT`; a message without a whole
    /// `genlmsghdr`, or from `RESV_START_OP` on with a reserved field or a
    /// flag the core does not take, is `EINVAL`; a command the family does
    /// not have, as a dump or not, `EOPNOTSUPP`. `Ok(true)` is a dump that
    /// began, which is not acknowledged.
    pub(super) fn generic(
        &self,
        s: &mut State,
        header: &Header,
        payload: &[u8],
        port: u32,
    ) -> Result<bool, Errno> {
        if header.kind != GENL_ID_CTRL {
            return Err(ENOENT);
        }
        if payload.len() < 4 {
            return Err(EINVAL);
        }
        let command = payload[0];
        let dump = header.flags & NLM_F_DUMP == NLM_F_DUMP;
        if command >= RESV_START_OP {
            let flags = if dump {
                header.flags & !NLM_F_DUMP
            } else {
                header.flags
            };
            if payload[2..4] != [0, 0] || flags & !(NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO) != 0 {
                return Err(EINVAL);
            }
        }
        let attributes = &payload[4..];
        match (command, dump) {
            (CTRL_CMD_GETFAMILY, false) => {
                let tb = parse(attributes, FAMILY_POLICY, false)?;
                let mut found = Err(EINVAL);
                if let Some(id) = tb[usize::from(CTRL_ATTR_FAMILY_ID)] {
                    found = if u16_of(id) == GENL_ID_CTRL {
                        Ok(())
                    } else {
                        Err(ENOENT)
                    };
                }
                if let Some(name) = tb[usize::from(CTRL_ATTR_FAMILY_NAME)] {
                    found = if is_ctrl(name) { Ok(()) } else { Err(ENOENT) };
                }
                found?;
                let reply = family(header.seq, port, 0);
                self.deliver(s, 0, 0, reply);
                Ok(false)
            }
            // `__netlink_dump_start` finds a dump running before
            // `genl_start` checks the attributes.
            (CTRL_CMD_GETFAMILY | CTRL_CMD_GETPOLICY, true) if s.done.is_some() => Err(EBUSY),
            // `ctrl_dumpfamily` lists every family in one go, so the first
            // part of the dump ends with its `NLMSG_DONE`.
            (CTRL_CMD_GETFAMILY, true) => {
                parse(attributes, FAMILY_POLICY, true)?;
                let mut messages = family(header.seq, port, NLM_F_MULTI);
                messages.extend(done(header.seq, port));
                self.deliver(s, 0, 0, messages);
                Ok(true)
            }
            // `ctrl_dumppolicy` stops with what it has put, so its
            // `NLMSG_DONE` comes in a part of its own.
            (CTRL_CMD_GETPOLICY, true) => {
                let tb = parse(attributes, POLICY_POLICY, true)?;
                let messages = policies(&tb, header.seq, port)?;
                self.deliver(s, 0, 0, messages);
                s.done = Some(done(header.seq, port));
                Ok(true)
            }
            _ => Err(EOPNOTSUPP),
        }
    }
}

/// The attributes of `bytes` by type, as `__nla_validate_parse` takes them
/// with `policy`: it stops at one too short or too long; a type of 0 or
/// past the policy's last is skipped, or with `strict` `EINVAL`, as are
/// bytes left over; each other is checked by [`validate`].
fn parse(mut bytes: &[u8], policy: Policy, strict: bool) -> Result<Vec<Option<&[u8]>>, Errno> {
    let mut tb = vec![None; policy.len()];
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if len < 4 || len > bytes.len() {
            break;
        }
        let raw = u16::from_le_bytes([bytes[2], bytes[3]]);
        let kind = usize::from(raw & 0x3fff);
        let value = &bytes[4..len];
        if kind == 0 || kind >= policy.len() {
            if strict {
                return Err(EINVAL);
            }
        } else {
            match policy[kind] {
                Some(of) => validate(of, raw & NLA_F_NESTED != 0, value, strict)?,
                // `NL_VALIDATE_UNSPEC`.
                None if strict => return Err(EINVAL),
                None => {}
            }
            tb[kind] = Some(value);
        }
        bytes = &bytes[align(len).min(bytes.len())..];
    }
    if strict && !bytes.is_empty() {
        return Err(EINVAL);
    }
    Ok(tb)
}
/// Checks an attribute of kind `of`, as `validate_nla`: strictly, an
/// integer of another length or one marked nested is `EINVAL`; a shorter
/// one is `ERANGE`. A string needs its NUL within its longest length and
/// one more byte (`EINVAL`), and without a last NUL must be no longer
/// (`ERANGE`).
fn validate(of: Kind, nested: bool, value: &[u8], strict: bool) -> Result<(), Errno> {
    let size = match of {
        Kind::U16 => 2,
        Kind::U32 => 4,
        Kind::NulString(_) => 0,
    };
    if strict && ((size != 0 && value.len() != size) || nested) {
        return Err(EINVAL);
    }
    if let Kind::NulString(longest) = of {
        let within = value.len().min(longest + 1);
        if within == 0 || !value[..within].contains(&0) {
            return Err(EINVAL);
        }
        let len = value.len() - usize::from(value[value.len() - 1] == 0);
        if len > longest {
            return Err(ERANGE);
        }
    } else if value.len() < size {
        return Err(ERANGE);
    }
    Ok(())
}
fn u16_of(value: &[u8]) -> u16 {
    u16::from_le_bytes([value[0], value[1]])
}
/// Whether a string attribute names `nlctrl`, up to its NUL.
fn is_ctrl(name: &[u8]) -> bool {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    &name[..end] == b"nlctrl"
}
/// A message of `nlctrl` with `command` (`genlmsg_put`) and `attributes`.
fn ctrl_message(command: u8, flags: u16, seq: u32, port: u32, attributes: &[u8]) -> Vec<u8> {
    let mut payload = vec![command, CTRL_VERSION, 0, 0];
    payload.extend_from_slice(attributes);
    message(GENL_ID_CTRL, flags, seq, port, &payload)
}
/// A dump's `NLMSG_DONE`.
fn done(seq: u32, port: u32) -> Vec<u8> {
    message(NLMSG_DONE, NLM_F_MULTI, seq, port, &0i32.to_le_bytes())
}
/// `nlctrl`'s `CTRL_CMD_NEWFAMILY`, as `ctrl_fill_info` makes it: its name,
/// ID, version, header size and last attribute (none), each command with
/// its flags, and its group.
fn family(seq: u32, port: u32, flags: u16) -> Vec<u8> {
    let mut out = Vec::new();
    attribute(&mut out, CTRL_ATTR_FAMILY_NAME, b"nlctrl\0");
    attribute(&mut out, CTRL_ATTR_FAMILY_ID, &GENL_ID_CTRL.to_le_bytes());
    attribute(
        &mut out,
        CTRL_ATTR_VERSION,
        &u32::from(CTRL_VERSION).to_le_bytes(),
    );
    attribute(&mut out, CTRL_ATTR_HDRSIZE, &0u32.to_le_bytes());
    attribute(&mut out, CTRL_ATTR_MAXATTR, &0u32.to_le_bytes());
    let mut ops = Vec::new();
    for (i, &(command, doit, dumpit)) in COMMANDS.iter().enumerate() {
        let mut op_flags = 0;
        if doit.is_some() {
            op_flags |= GENL_CMD_CAP_DO;
        }
        if dumpit.is_some() {
            op_flags |= GENL_CMD_CAP_DUMP;
        }
        op_flags |= GENL_CMD_CAP_HASPOL;
        let mut op = Vec::new();
        attribute(&mut op, CTRL_ATTR_OP_ID, &u32::from(command).to_le_bytes());
        attribute(&mut op, CTRL_ATTR_OP_FLAGS, &op_flags.to_le_bytes());
        attribute(&mut ops, i as u16 + 1, &op);
    }
    attribute(&mut out, CTRL_ATTR_OPS, &ops);
    let mut group = Vec::new();
    attribute(
        &mut group,
        CTRL_ATTR_MCAST_GRP_ID,
        &u32::from(GENL_ID_CTRL).to_le_bytes(),
    );
    attribute(&mut group, CTRL_ATTR_MCAST_GRP_NAME, b"notify\0");
    let mut groups = Vec::new();
    attribute(&mut groups, 1, &group);
    attribute(&mut out, CTRL_ATTR_MCAST_GROUPS, &groups);
    ctrl_message(CTRL_CMD_NEWFAMILY, flags, seq, port, &out)
}
/// The messages of a `CTRL_CMD_GETPOLICY` dump, as `ctrl_dumppolicy_start`
/// and `ctrl_dumppolicy` make them: the family by ID or else by name
/// (`EINVAL` for neither, `ENOENT` for another); for each of its commands,
/// or the one `CTRL_ATTR_OP` names (`ENOENT` for another), the index of
/// the policy of its `doit` and `dumpit`; then each attribute of each of
/// those policies, a message each.
fn policies(tb: &[Option<&[u8]>], seq: u32, port: u32) -> Result<Vec<u8>, Errno> {
    let id = match (
        tb[usize::from(CTRL_ATTR_FAMILY_ID)],
        tb[usize::from(CTRL_ATTR_FAMILY_NAME)],
    ) {
        (Some(id), _) => u16_of(id),
        (None, Some(name)) if is_ctrl(name) => GENL_ID_CTRL,
        (None, Some(_)) => return Err(ENOENT),
        (None, None) => return Err(EINVAL),
    };
    if id != GENL_ID_CTRL {
        return Err(ENOENT);
    }
    let commands: Vec<_> = match tb[usize::from(CTRL_ATTR_OP)] {
        Some(op) => {
            let op = u32::from_le_bytes(op[..4].try_into().unwrap_or_default());
            let found = COMMANDS
                .iter()
                .find(|&&(command, ..)| u32::from(command) == op)
                .ok_or(ENOENT)?;
            vec![*found]
        }
        None => COMMANDS.to_vec(),
    };
    // `netlink_policy_dump_add_policy`: each policy once, in the order
    // first met.
    let mut table: Vec<Policy> = Vec::new();
    let mut out = Vec::new();
    let id_attribute = |out: &mut Vec<u8>| attribute(out, CTRL_ATTR_FAMILY_ID, &id.to_le_bytes());
    let mut each = Vec::new();
    for &(command, doit, dumpit) in &commands {
        let mut op = Vec::new();
        if let Some(policy) = doit {
            let at = index(policy, &mut table);
            attribute(&mut op, CTRL_ATTR_POLICY_DO, &at.to_le_bytes());
        }
        if let Some(policy) = dumpit {
            let at = index(policy, &mut table);
            attribute(&mut op, CTRL_ATTR_POLICY_DUMP, &at.to_le_bytes());
        }
        each.push((command, op));
    }
    for (command, op) in each {
        let mut attributes = Vec::new();
        id_attribute(&mut attributes);
        let mut nest = Vec::new();
        attribute(&mut nest, u16::from(command) | NLA_F_NESTED, &op);
        attribute(&mut attributes, CTRL_ATTR_OP_POLICY | NLA_F_NESTED, &nest);
        out.extend(ctrl_message(
            CTRL_CMD_GETPOLICY,
            NLM_F_MULTI,
            seq,
            port,
            &attributes,
        ));
    }
    for (at, policy) in table.iter().enumerate() {
        for (kind, of) in policy.iter().enumerate() {
            let Some(of) = of else { continue };
            let mut attributes = Vec::new();
            id_attribute(&mut attributes);
            let mut description = Vec::new();
            match *of {
                Kind::U16 | Kind::U32 => {
                    let (max, kind) = if matches!(of, Kind::U16) {
                        (u64::from(u16::MAX), NL_ATTR_TYPE_U16)
                    } else {
                        (u64::from(u32::MAX), NL_ATTR_TYPE_U32)
                    };
                    attribute(
                        &mut description,
                        NL_POLICY_TYPE_ATTR_MIN_VALUE_U,
                        &0u64.to_le_bytes(),
                    );
                    attribute(
                        &mut description,
                        NL_POLICY_TYPE_ATTR_MAX_VALUE_U,
                        &max.to_le_bytes(),
                    );
                    attribute(
                        &mut description,
                        NL_POLICY_TYPE_ATTR_TYPE,
                        &kind.to_le_bytes(),
                    );
                }
                Kind::NulString(longest) => {
                    attribute(
                        &mut description,
                        NL_POLICY_TYPE_ATTR_MAX_LENGTH,
                        &(longest as u32).to_le_bytes(),
                    );
                    attribute(
                        &mut description,
                        NL_POLICY_TYPE_ATTR_TYPE,
                        &NL_ATTR_TYPE_NUL_STRING.to_le_bytes(),
                    );
                }
            }
            let mut inner = Vec::new();
            attribute(&mut inner, kind as u16 | NLA_F_NESTED, &description);
            let mut outer = Vec::new();
            attribute(&mut outer, at as u16 | NLA_F_NESTED, &inner);
            attribute(&mut attributes, CTRL_ATTR_POLICY | NLA_F_NESTED, &outer);
            out.extend(ctrl_message(
                CTRL_CMD_GETPOLICY,
                NLM_F_MULTI,
                seq,
                port,
                &attributes,
            ));
        }
    }
    Ok(out)
}
/// The index of `policy` in `table`, added at the end when first met.
fn index(policy: Policy, table: &mut Vec<Policy>) -> u32 {
    let at = table
        .iter()
        .position(|&p| core::ptr::eq(p, policy))
        .unwrap_or_else(|| {
            table.push(policy);
            table.len() - 1
        });
    at as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_message_is_as_ctrl_fill_info_makes_it() {
        let m = family(7, 9, 0);
        // nlmsghdr, genlmsghdr, then name 12, ID 8, three words 24, the
        // two commands 44 and the group 28.
        assert_eq!(m.len(), 16 + 4 + 12 + 8 + 24 + 44 + 28);
        assert_eq!(u16::from_le_bytes([m[4], m[5]]), GENL_ID_CTRL);
        assert_eq!(&m[16..20], &[CTRL_CMD_NEWFAMILY, 2, 0, 0]);
        assert_eq!(&m[24..31], b"nlctrl\0");
    }

    #[test]
    fn attributes_are_checked_as_the_policy_says() {
        let attr = |kind: u16, value: &[u8]| {
            let mut out = Vec::new();
            attribute(&mut out, kind, value);
            out
        };
        // Liberal: a longer integer is taken, a shorter one is ERANGE, an
        // unknown type is skipped.
        assert!(parse(&attr(1, &[16, 0, 0, 0]), FAMILY_POLICY, false).is_ok());
        assert_eq!(
            parse(&attr(1, &[16]), FAMILY_POLICY, false).err(),
            Some(ERANGE)
        );
        assert!(parse(&attr(9, &[0; 4]), FAMILY_POLICY, false).is_ok());
        // Strict: both are EINVAL, as is one marked nested.
        assert_eq!(
            parse(&attr(1, &[16, 0, 0, 0]), FAMILY_POLICY, true).err(),
            Some(EINVAL)
        );
        assert_eq!(
            parse(&attr(9, &[0; 4]), FAMILY_POLICY, true).err(),
            Some(EINVAL)
        );
        assert_eq!(
            parse(&attr(1 | NLA_F_NESTED, &[16, 0]), FAMILY_POLICY, true).err(),
            Some(EINVAL)
        );
        // A name needs its NUL within 16 bytes, and no more than 15 before
        // a last NUL.
        assert_eq!(
            parse(&attr(2, &[b'a'; 16]), FAMILY_POLICY, false).err(),
            Some(EINVAL)
        );
        let mut long = vec![b'a'; 20];
        long[3] = 0;
        assert_eq!(
            parse(&attr(2, &long), FAMILY_POLICY, false).err(),
            Some(ERANGE)
        );
        let mut fifteen = vec![b'a'; 15];
        fifteen.push(0);
        assert!(parse(&attr(2, &fifteen), FAMILY_POLICY, false).is_ok());
    }

    #[test]
    fn policy_dump_lists_each_policy_once() {
        let mut name = Vec::new();
        attribute(&mut name, CTRL_ATTR_FAMILY_NAME, b"nlctrl\0");
        let tb = parse(&name, POLICY_POLICY, true).unwrap();
        let out = policies(&tb, 1, 2).unwrap();
        let mut count = 0;
        let mut at = 0;
        while at < out.len() {
            count += 1;
            at += align(u32::from_le_bytes(out[at..at + 4].try_into().unwrap()) as usize);
        }
        // Two commands, then two attributes of one policy and three of the
        // other.
        assert_eq!(count, 2 + 2 + 3);
        let mut op = name.clone();
        attribute(&mut op, CTRL_ATTR_OP, &1u32.to_le_bytes());
        let tb = parse(&op, POLICY_POLICY, true).unwrap();
        assert_eq!(policies(&tb, 1, 2).err(), Some(ENOENT));
        let tb = parse(&[], POLICY_POLICY, true).unwrap();
        assert_eq!(policies(&tb, 1, 2).err(), Some(EINVAL));
    }
}
