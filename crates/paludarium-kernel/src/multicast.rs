//! Multicast groups (Linux's `igmp.c` and IPv6's `mcast.c`): the groups each
//! device has joined, which say what comes in through it
//! (`ip_check_mc_rcu`, `ipv6_chk_mcast_addr`), and the memberships of each
//! socket, which make a device join and leave. No IGMP or MLD packet is
//! sent, as nothing here would see one.

use crate::inet::Network;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use paludarium_types::Errno;

const EADDRINUSE: Errno = Errno(98);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENOBUFS: Errno = Errno(105);
const ENODEV: Errno = Errno(19);

/// `IGMP_ALL_HOSTS`, the group every device is in while it is up
/// (`ip_mc_up`).
pub(crate) const ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
/// The most memberships a socket has (`net.ipv4.igmp_max_memberships`).
const MAX_MEMBERSHIPS: usize = 20;

/// The most sources an IPv4 filter has (`net.ipv4.igmp_max_msf`).
pub(crate) const MAX_SOURCES4: u32 = 10;
/// The most an IPv6 one has (`net.ipv6.mld_max_msf`).
pub(crate) const MAX_SOURCES6: u32 = 64;

/// Whether a filter's sources are those it keeps out (`MCAST_EXCLUDE`, 0) or
/// those it lets in (`MCAST_INCLUDE`, 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Exclude,
    Include,
}
impl Mode {
    /// The mode of the number an option gives.
    pub(crate) fn read(mode: u32) -> Option<Self> {
        match mode {
            0 => Some(Self::Exclude),
            1 => Some(Self::Include),
            _ => None,
        }
    }
}

/// The source filter of a socket's membership (`sfmode`, `sflist`): its
/// mode, and its sources, the newest last, or none while it has no list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Filter<A> {
    pub(crate) mode: Mode,
    list: Option<Vec<A>>,
}
impl<A: Copy + PartialEq> Filter<A> {
    /// The filter a membership begins with, of no sources.
    const fn new(mode: Mode) -> Self {
        Self { mode, list: None }
    }
    pub(crate) fn sources(&self) -> &[A] {
        self.list.as_deref().unwrap_or_default()
    }
    /// Whether it lets in what comes from `source`.
    fn allows(&self, source: A) -> bool {
        self.sources().contains(&source) == (self.mode == Mode::Include)
    }
    /// Adds `source` to it, of at most `most`, or takes it away, for the
    /// device that has `groups` too (`ip_mc_source`, `ip6_mc_source`): a
    /// filter with no list first becomes one of `mode`, and one with a list
    /// is of it already (`EINVAL`); `EADDRNOTAVAIL` to add one it has or to
    /// take away one it has not; `ENOBUFS` past the most. Whether the
    /// membership ends instead, as the last source it lets in goes.
    fn change(
        &mut self,
        groups: &mut Groups<A>,
        group: A,
        (add, mode, most): (bool, Mode, u32),
        source: A,
    ) -> Result<bool, Errno> {
        if self.mode != mode {
            if self.list.is_some() {
                return Err(Errno::EINVAL);
            }
            groups.add(group, mode, &[], false);
            groups.remove(group, self.mode, &[], false);
            self.mode = mode;
        }
        let at = self.sources().iter().position(|s| *s == source);
        if add {
            if self.sources().len() >= most as usize {
                return Err(ENOBUFS);
            }
            if at.is_some() {
                return Err(EADDRNOTAVAIL);
            }
            self.list.get_or_insert_default().push(source);
            groups.add(group, mode, &[source], true);
            return Ok(false);
        }
        let (Some(at), Some(list)) = (at, &mut self.list) else {
            return Err(EADDRNOTAVAIL);
        };
        if list.len() == 1 && mode == Mode::Include {
            return Ok(true);
        }
        groups.remove(group, mode, &[source], true);
        list.remove(at);
        Ok(false)
    }
    /// Becomes the filter of `mode` and `sources`, for the device that has
    /// `groups` too (`ip_mc_msfilter`, `ip6_mc_msfilter`).
    fn set(&mut self, groups: &mut Groups<A>, group: A, mode: Mode, sources: Vec<A>) {
        groups.add(group, mode, &sources, false);
        groups.remove(group, self.mode, self.sources(), false);
        self.mode = mode;
        self.list = (!sources.is_empty()).then_some(sources);
    }
}

/// How many memberships of each mode there are: those that exclude, and
/// those that include.
type Counts = [u32; 2];

/// A group a device has joined (`ip_mc_list`, `ifmcaddr6`): how many times
/// it has been, by memberships of which modes (`sfcount`), and the sources
/// their filters name (`ip_sf_list`), each by how many of which modes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Group<A> {
    group: A,
    users: u32,
    /// When it was joined anew, by the host's monotonic clock
    /// (`mca_cstamp`).
    created: u64,
    modes: Counts,
    sources: Vec<(A, Counts)>,
}
/// The groups a device has joined (`in_dev->mc_list`, `idev->mc_list`), the
/// newest first. Of IPv6's, those that sockets joined
/// ([`Network::in_group6`] has the rest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Groups<A> {
    list: Vec<Group<A>>,
}
impl<A> Default for Groups<A> {
    fn default() -> Self {
        Self { list: Vec::new() }
    }
}
impl<A: Copy + PartialEq> Groups<A> {
    fn group(&mut self, group: A) -> Option<&mut Group<A>> {
        self.list.iter_mut().find(|g| g.group == group)
    }
    /// The device joins `group` once more at `now`, by a membership that
    /// begins with `mode` (`____ip_mc_inc_group`, `__ipv6_dev_mc_inc`):
    /// whether it had not.
    pub(crate) fn join(&mut self, group: A, mode: Mode, now: u64) -> bool {
        let new = match self.group(group) {
            Some(g) => {
                g.users += 1;
                false
            }
            None => {
                self.list.insert(
                    0,
                    Group {
                        group,
                        users: 1,
                        created: now,
                        modes: [0; 2],
                        sources: Vec::new(),
                    },
                );
                true
            }
        };
        self.add(group, mode, &[], false);
        new
    }
    /// The device leaves `group` once, as a membership of `filter` does, for
    /// good with its last user (`ip_mc_leave_src` and `__ip_mc_dec_group`,
    /// `ip6_mc_leave_src` and `__ipv6_dev_mc_dec`): when it was joined, if
    /// it is left for good.
    fn leave(&mut self, group: A, filter: &Filter<A>) -> Option<u64> {
        self.remove(group, filter.mode, filter.sources(), false);
        let mut gone = None;
        self.list.retain_mut(|g| {
            if g.group == group {
                g.users -= 1;
                if g.users == 0 {
                    gone = Some(g.created);
                }
            }
            g.users > 0
        });
        gone
    }
    /// Each group, the newest first, with its users and when it was joined
    /// (`in_dev_dump_ifmcaddr`).
    pub(crate) fn listed(&self) -> impl Iterator<Item = (A, u32, u64)> + '_ {
        self.list.iter().map(|g| (g.group, g.users, g.created))
    }
    /// A membership of `mode` there names `sources`, as another or, as
    /// `only` those, one there already (`ip_mc_add_src`, `ip6_mc_add_src`).
    fn add(&mut self, group: A, mode: Mode, sources: &[A], only: bool) {
        let Some(g) = self.group(group) else {
            return;
        };
        if !only {
            g.modes[mode as usize] += 1;
        }
        for &source in sources {
            match g.sources.iter_mut().find(|(s, _)| *s == source) {
                Some((_, counts)) => counts[mode as usize] += 1,
                None => {
                    let mut counts = [0; 2];
                    counts[mode as usize] = 1;
                    g.sources.push((source, counts));
                }
            }
        }
    }
    /// And names them no more (`ip_mc_del_src`, `ip6_mc_del_src`).
    fn remove(&mut self, group: A, mode: Mode, sources: &[A], only: bool) {
        let Some(g) = self.group(group) else {
            return;
        };
        if !only {
            let Some(left) = g.modes[mode as usize].checked_sub(1) else {
                return;
            };
            g.modes[mode as usize] = left;
        }
        for source in sources {
            g.sources.retain_mut(|(s, counts)| {
                if s == source {
                    counts[mode as usize] = counts[mode as usize].saturating_sub(1);
                }
                *counts != [0; 2]
            });
        }
    }
    /// Whether the device has joined `group` and takes what comes to it from
    /// `source`, which may be unspecified (`ip_check_mc_rcu`,
    /// `ipv6_chk_mcast_addr`): where a membership includes it, or one that
    /// excludes does not name it.
    pub(crate) fn takes(&self, group: A, source: Option<A>) -> bool {
        let Some(g) = self.list.iter().find(|g| g.group == group) else {
            return false;
        };
        let Some(source) = source else {
            return true;
        };
        let [exclude, include] = g
            .sources
            .iter()
            .find(|(s, _)| *s == source)
            .map_or([0; 2], |(_, counts)| *counts);
        include != 0 || exclude != g.modes[Mode::Exclude as usize]
    }
}
/// A change of a device's IPv4 groups that netlink tells of
/// (`inet_ifmcaddr_notify`): a group the device `index` has joined anew, of
/// its one user, or left for good, of none, and when it was joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Told4 {
    pub index: i32,
    pub group: Ipv4Addr,
    pub joined: bool,
    pub created: u64,
}
impl Told4 {
    /// Its users, as `inet_fill_ifmcaddr` gives them.
    pub(crate) fn users(&self) -> u32 {
        u32::from(self.joined)
    }
}
/// The device `index`, of `groups`, out of its namespace, leaves the
/// all-hosts group once (`ip_mc_down`): what netlink tells of it.
pub(crate) fn leave_all_hosts(groups: &mut Groups<Ipv4Addr>, index: i32) -> Option<Told4> {
    let created = groups.leave(ALL_HOSTS, &Filter::new(Mode::Exclude))?;
    Some(Told4 {
        index,
        group: ALL_HOSTS,
        joined: false,
        created,
    })
}
/// The source a device's filters look at, none for an unspecified one.
fn source4(source: Ipv4Addr) -> Option<Ipv4Addr> {
    (!source.is_unspecified()).then_some(source)
}

/// A socket's membership, of the group and device `at`.
#[derive(Clone, Debug)]
pub(crate) struct Member<M, A> {
    at: M,
    filter: Filter<A>,
}
pub(crate) type Member4 = Member<Membership, Ipv4Addr>;
pub(crate) type Member6 = Member<Membership6, Ipv6Addr>;

/// A membership a socket asks for or has (`struct ip_mreqn`): the group,
/// and the device, by its index or an address of it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Membership {
    pub(crate) group: Ipv4Addr,
    pub(crate) address: Ipv4Addr,
    pub(crate) index: i32,
}
impl Membership {
    /// Reads an `ip_mreqn`, or an `ip_mreq`, which has no index.
    pub(crate) fn read(raw: &[u8]) -> Self {
        let word = |at: usize| {
            raw.get(at..at + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
        };
        Self {
            group: word(0).unwrap_or_default().into(),
            address: word(4).unwrap_or_default().into(),
            index: i32::from_le_bytes(word(8).unwrap_or_default()),
        }
    }
}

/// Whether a socket of `memberships`, the newest first, takes a datagram
/// from `source` to `group` that came in on the device `dif`: as its filter
/// there has it, or, as no member there, while it takes every group's
/// (`IP_MULTICAST_ALL`), as `ip_mc_sf_allow` decides.
pub(crate) fn allows(
    memberships: &[Member4],
    all: bool,
    (source, group): (Ipv4Addr, Ipv4Addr),
    dif: u32,
) -> bool {
    memberships
        .iter()
        .find(|m| m.at.group == group && u32::try_from(m.at.index) == Ok(dif))
        .map_or(all, |m| m.filter.allows(source))
}

/// An IPv6 membership a socket asks for or has (`struct ipv6_mreq`): the
/// group, and the device's index.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Membership6 {
    pub(crate) group: Ipv6Addr,
    pub(crate) index: i32,
}
impl Membership6 {
    /// Reads an `ipv6_mreq`.
    pub(crate) fn read(raw: &[u8; 20]) -> Self {
        let mut group = [0; 16];
        group.copy_from_slice(&raw[..16]);
        Self {
            group: group.into(),
            index: i32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]),
        }
    }
}

/// Whether a socket of `memberships`, the newest first, takes a datagram
/// from `source` to the IPv6 group `group`, on whatever device: as the
/// filter of the newest has it, or, as no member, while it takes every
/// group's (`IPV6_MULTICAST_ALL`), as `inet6_mc_check` decides.
pub(crate) fn allows6(
    memberships: &[Member6],
    all: bool,
    (source, group): (Ipv6Addr, Ipv6Addr),
) -> bool {
    memberships
        .iter()
        .find(|m| m.at.group == group)
        .map_or(all, |m| m.filter.allows(source))
}
/// The scope of an IPv6 group (`IPV6_ADDR_MC_SCOPE`): 1 is the interface's
/// own.
pub(crate) fn scope6(group: Ipv6Addr) -> u8 {
    group.octets()[1] & 0xf
}

impl Network {
    /// The device that has the IPv4 address `ip` (`__ip_dev_find`): by its
    /// addresses, else by the local table's routes.
    pub(crate) fn device_with4(&self, ip: Ipv4Addr, now: Option<u64>) -> Option<i32> {
        let addresses = self.addresses_at(now);
        addresses.device_of4(ip).or_else(|| {
            addresses
                .local4(ip)
                .then(|| addresses.lookup4(ip).ok())
                .flatten()
                .and_then(|route| i32::try_from(route.oif).ok())
        })
    }
    /// The device the route to `group` goes out through, if one does.
    fn device_to4(&self, group: Ipv4Addr, now: Option<u64>) -> Option<i32> {
        use crate::interface::Kind;
        let route = self.addresses_at(now).lookup4(group).ok()?;
        matches!(route.kind, Kind::Unicast | Kind::Broadcast | Kind::Local)
            .then(|| i32::try_from(route.oif).ok())
            .flatten()
    }
    /// Whether `group`'s route goes out through `lo`.
    pub(crate) fn group_on_lo(&self, group: Ipv4Addr, now: Option<u64>) -> bool {
        self.device_to4(group, now) == Some(crate::netdev::LOOPBACK_INDEX)
    }
    /// The device `asked` names (`ip_mc_find_dev`): that of its index, of
    /// its address, or of the route to the group.
    fn group_device(&self, asked: &Membership, now: Option<u64>) -> Option<i32> {
        if asked.index != 0 {
            return self.has_device(asked.index).then_some(asked.index);
        }
        if asked.address.is_unspecified() {
            return self.device_to4(asked.group, now);
        }
        self.device_with4(asked.address, now)
    }
    /// Whether the device `index` has joined `group` and takes what comes to
    /// it from `source` ([`Groups::takes`]).
    pub(crate) fn in_group4(&self, index: i32, source: Ipv4Addr, group: Ipv4Addr) -> bool {
        self.devices()
            .by_index(index)
            .is_some_and(|d| d.groups4.takes(group, source4(source)))
    }
    /// Does `change` with the IPv4 groups of the device `index`, or with none
    /// while it is gone.
    fn with_groups4<R>(&self, index: i32, change: impl FnOnce(&mut Groups<Ipv4Addr>) -> R) -> R {
        match self.devices().by_index_mut(index) {
            Some(device) => change(&mut device.groups4),
            None => change(&mut Groups::default()),
        }
    }
    /// The device `index` joins `group` at `now`, kept for netlink to tell
    /// of as it does it anew ([`Network::groups_told4`]).
    fn join_group4(&self, index: i32, group: Ipv4Addr, mode: Mode, now: u64) {
        let mut devices = self.devices();
        if let Some((groups, told)) = devices.groups4_of(index)
            && groups.join(group, mode, now)
        {
            told.push(Told4 {
                index,
                group,
                joined: true,
                created: now,
            });
        }
    }
    /// The device `index` leaves `group` once, as a membership of `filter`
    /// does, kept for netlink to tell of as it leaves it for good.
    fn leave_group4(&self, index: i32, group: Ipv4Addr, filter: &Filter<Ipv4Addr>) {
        let mut devices = self.devices();
        if let Some((groups, told)) = devices.groups4_of(index)
            && let Some(created) = groups.leave(group, filter)
        {
            told.push(Told4 {
                index,
                group,
                joined: false,
                created,
            });
        }
    }
    /// What the IPv4 groups' changes since the last call were, in their
    /// order, for netlink to tell of.
    pub(crate) fn groups_told4(&self) -> Vec<Told4> {
        core::mem::take(&mut self.devices().told4)
    }
    /// The device `index` joins `group` by itself at `now`, or leaves it.
    pub(crate) fn change_group4(&self, index: i32, group: Ipv4Addr, join: bool, now: u64) {
        if join {
            self.join_group4(index, group, Mode::Exclude, now);
        } else {
            self.leave_group4(index, group, &Filter::new(Mode::Exclude));
        }
    }
    /// A socket of `memberships` joins the group `asked`, with a filter of
    /// `mode` (`__ip_mc_join_group`): `EINVAL` for no group, `ENODEV` for no
    /// device, `EADDRINUSE` as a member there already, `ENOBUFS` at the
    /// most.
    pub(crate) fn join4(
        &self,
        memberships: &mut Vec<Member4>,
        asked: Membership,
        mode: Mode,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = self.group_device(&asked, now).ok_or(ENODEV)?;
        if member4(memberships, asked.group, index).is_some() {
            return Err(EADDRINUSE);
        }
        if memberships.len() >= MAX_MEMBERSHIPS {
            return Err(ENOBUFS);
        }
        memberships.insert(
            0,
            Member {
                at: Membership { index, ..asked },
                filter: Filter::new(mode),
            },
        );
        self.join_group4(index, asked.group, mode, now.unwrap_or(0));
        Ok(())
    }
    /// A socket of `memberships` leaves the group `asked`
    /// (`ip_mc_leave_group`), on the device it names, or, naming one there
    /// is not, by the address it was joined with: `ENODEV` for none at all,
    /// `EADDRNOTAVAIL` as no member. The device it joined leaves the group,
    /// as Linux master has it.
    pub(crate) fn leave4(
        &self,
        memberships: &mut Vec<Member4>,
        asked: Membership,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        let index = match self.group_device(&asked, now) {
            Some(index) => index,
            None if asked.index == 0 && asked.address.is_unspecified() => return Err(ENODEV),
            None => asked.index,
        };
        let at = memberships
            .iter()
            .position(|m| {
                m.at.group == asked.group
                    && if index != 0 {
                        m.at.index == index
                    } else {
                        m.at.address == asked.address
                    }
            })
            .ok_or(EADDRNOTAVAIL)?;
        let left = memberships.remove(at);
        self.leave_group4(left.at.index, left.at.group, &left.filter);
        Ok(())
    }
    /// A socket of `memberships` that goes leaves them all
    /// (`ip_mc_drop_socket`).
    pub(crate) fn drop4(&self, memberships: &[Member4]) {
        for m in memberships {
            self.leave_group4(m.at.index, m.at.group, &m.filter);
        }
    }
    /// A socket of `memberships` adds `source` to the filter of the one
    /// `asked`, which is of `mode`, or takes it away (`ip_mc_source`):
    /// `EINVAL` for no group or as no member there, `ENODEV` for no device,
    /// and [`Filter::change`]'s.
    pub(crate) fn source4(
        &self,
        memberships: &mut Vec<Member4>,
        asked: Membership,
        (add, mode): (bool, Mode),
        source: Ipv4Addr,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        let group = asked.group;
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = self.group_device(&asked, now).ok_or(ENODEV)?;
        let at = member4(memberships, group, index).ok_or(Errno::EINVAL)?;
        let filter = &mut memberships[at].filter;
        let ends = self.with_groups4(index, |groups| {
            filter.change(groups, group, (add, mode, MAX_SOURCES4), source)
        })?;
        if ends {
            return self.leave4(memberships, Membership { index, ..asked }, now);
        }
        Ok(())
    }
    /// A socket of `memberships` gives the one `asked` the filter of `mode`
    /// and `sources` (`ip_mc_msfilter`), and leaves it for one that lets
    /// nothing in: `EINVAL` for no group, no mode or as no member there,
    /// `ENODEV` for no device.
    pub(crate) fn filter4(
        &self,
        memberships: &mut Vec<Member4>,
        asked: Membership,
        mode: u32,
        sources: Vec<Ipv4Addr>,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        let group = asked.group;
        let mode = Mode::read(mode).ok_or(Errno::EINVAL)?;
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = self.group_device(&asked, now).ok_or(ENODEV)?;
        if mode == Mode::Include && sources.is_empty() {
            return self.leave4(memberships, Membership { index, ..asked }, now);
        }
        let at = member4(memberships, group, index).ok_or(Errno::EINVAL)?;
        let filter = &mut memberships[at].filter;
        self.with_groups4(index, |groups| filter.set(groups, group, mode, sources));
        Ok(())
    }
    /// The filter of the one of `memberships` that is `asked`
    /// (`ip_mc_msfget`, and `ip_mc_gsfget` for one `by_index`, which looks
    /// for no device): `EINVAL` for no group, `ENODEV` for no device,
    /// `EADDRNOTAVAIL` as no member there.
    pub(crate) fn filter_of4<'m>(
        &self,
        memberships: &'m [Member4],
        asked: Membership,
        by_index: bool,
        now: Option<u64>,
    ) -> Result<&'m Filter<Ipv4Addr>, Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = if by_index {
            asked.index
        } else {
            self.group_device(&asked, now).ok_or(ENODEV)?
        };
        let at = member4(memberships, asked.group, index).ok_or(EADDRNOTAVAIL)?;
        Ok(&memberships[at].filter)
    }
    /// Whether a packet from `src` to the group `group` in through the
    /// device `index` comes here (`ip_route_input_mc`): the device has
    /// joined it, and `src` is one it may come from (`ip_mc_validate_source`,
    /// with the reverse path filtering `rp_filter`).
    pub(crate) fn takes_group4(
        &self,
        index: i32,
        src: Ipv4Addr,
        group: Ipv4Addr,
        now: Option<u64>,
    ) -> bool {
        if !self.in_group4(index, src, group) {
            return false;
        }
        let rp_filter = self.rp_filter(index);
        if src.is_multicast() || src.is_broadcast() || src.is_loopback() {
            return false;
        }
        if src.is_unspecified() {
            return local_group(group);
        }
        self.addresses_at(now)
            .validate_source4_on(src, 0, 0, rp_filter, index)
            .is_ok()
    }
}
impl Network {
    /// Whether the device `index` is in the IPv6 group `group` and takes what
    /// comes to it from `source` (`ipv6_chk_mcast_addr`): as one a socket
    /// joined, with its filters ([`Groups::takes`]), the all-nodes groups
    /// every device with IPv6 is in (`ipv6_add_dev`), the solicited-node
    /// group of an address of a veth end's (`addrconf_join_solict`), or the
    /// all-routers groups of one that forwards (`dev_forward_change`).
    pub(crate) fn in_group6(
        &self,
        index: i32,
        source: Ipv6Addr,
        group: Ipv6Addr,
        now: Option<u64>,
    ) -> bool {
        let source = (!source.is_unspecified()).then_some(source);
        let (joined, veth, routes) = {
            let devices = self.devices();
            let Some(device) = devices.by_index(index) else {
                return false;
            };
            (
                device.groups6.takes(group, source),
                device.veth.is_some(),
                device.conf6.forwarding != 0,
            )
        };
        let first = group.segments()[0];
        let nodes = |id: u16| group.segments() == [first, 0, 0, 0, 0, 0, 0, id];
        joined
            || nodes(1) && matches!(first, 0xff01 | 0xff02)
            || veth && routes && nodes(2) && matches!(first, 0xff01 | 0xff02 | 0xff05)
            || veth && self.addresses_at(now).solicits6(index, group)
    }
    /// Whether the device `index` has IPv6 at all (`in6_dev_get`): not a
    /// veth end of an MTU below 1280.
    fn has_ipv6(&self, index: i32) -> bool {
        self.devices()
            .by_index(index)
            .is_some_and(|d| d.veth.as_ref().is_none_or(|v| v.mtu >= 1280))
    }
    /// Does `change` with the IPv6 groups of the device `index`, or with none
    /// while it is gone.
    fn with_groups6<R>(&self, index: i32, change: impl FnOnce(&mut Groups<Ipv6Addr>) -> R) -> R {
        match self.devices().by_index_mut(index) {
            Some(device) => change(&mut device.groups6),
            None => change(&mut Groups::default()),
        }
    }
    /// The device `asked` names (`ip6_mc_find_dev`): that of its index, or of
    /// the route to the group.
    fn group_device6(&self, asked: Membership6, now: Option<u64>) -> Option<i32> {
        if asked.index != 0 {
            return self.has_device(asked.index).then_some(asked.index);
        }
        let route = self.addresses_at(now).lookup6(asked.group).ok()?;
        i32::try_from(route.oif).ok()
    }
    /// A socket of `memberships` joins the IPv6 group `asked`, with a filter
    /// of `mode` (`__ipv6_sock_mc_join`): `EINVAL` for no group,
    /// `EADDRINUSE` as a member there, or anywhere for no device named,
    /// `ENODEV` for none there is or routes to the group, `EINVAL` for one
    /// without IPv6.
    pub(crate) fn join6(
        &self,
        memberships: &mut Vec<Member6>,
        asked: Membership6,
        mode: Mode,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        if member6(memberships, asked, true).is_some() {
            return Err(EADDRINUSE);
        }
        let index = self.group_device6(asked, now).ok_or(ENODEV)?;
        if !self.has_ipv6(index) {
            return Err(Errno::EINVAL);
        }
        memberships.insert(
            0,
            Member {
                at: Membership6 { index, ..asked },
                filter: Filter::new(mode),
            },
        );
        self.with_groups6(index, |groups| {
            groups.join(asked.group, mode, now.unwrap_or(0))
        });
        Ok(())
    }
    /// A socket of `memberships` leaves the IPv6 group `asked`
    /// (`ipv6_sock_mc_drop`), on the device it names or the newest there is:
    /// `EINVAL` for no group, `EADDRNOTAVAIL` as no member.
    pub(crate) fn leave6(
        &self,
        memberships: &mut Vec<Member6>,
        asked: Membership6,
    ) -> Result<(), Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let at = member6(memberships, asked, true).ok_or(EADDRNOTAVAIL)?;
        let left = memberships.remove(at);
        self.with_groups6(left.at.index, |g| {
            g.leave(left.at.group, &left.filter);
        });
        Ok(())
    }
    /// A socket of `memberships` that goes leaves them all
    /// (`__ipv6_sock_mc_close`).
    pub(crate) fn drop6(&self, memberships: &[Member6]) {
        for m in memberships {
            self.with_groups6(m.at.index, |groups| {
                groups.leave(m.at.group, &m.filter);
            });
        }
    }
    /// A socket of `memberships` adds `source` to the filter of the one
    /// `asked`, the newest there is where it names no device, which is of
    /// `mode`, or takes it away (`ip6_mc_source`): `EINVAL` for no group or
    /// as no member, `ENODEV` for no device or one without IPv6, and
    /// [`Filter::change`]'s. The device named, or of the route to the group,
    /// filters too, whichever the membership is on. As Linux master has it,
    /// a filter whose last source goes has no list.
    pub(crate) fn source6(
        &self,
        memberships: &mut Vec<Member6>,
        asked: Membership6,
        (add, mode): (bool, Mode),
        source: Ipv6Addr,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        let group = asked.group;
        let index = self.filtering_device6(asked, now)?;
        let at = member6(memberships, asked, true).ok_or(Errno::EINVAL)?;
        let filter = &mut memberships[at].filter;
        let ends = self.with_groups6(index, |groups| {
            filter.change(groups, group, (add, mode, MAX_SOURCES6), source)
        })?;
        if filter.sources().is_empty() {
            filter.list = None;
        }
        if ends {
            return self.leave6(memberships, asked);
        }
        Ok(())
    }
    /// The device whose filters a source or filter of `asked` changes
    /// (`ip6_mc_find_idev`): `EINVAL` for no group, `ENODEV` for none, or one
    /// without IPv6.
    fn filtering_device6(&self, asked: Membership6, now: Option<u64>) -> Result<i32, Errno> {
        if !asked.group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        self.group_device6(asked, now)
            .filter(|&index| self.has_ipv6(index))
            .ok_or(ENODEV)
    }
    /// A socket of `memberships` gives the one `asked`, on the very device
    /// it names, the filter of `mode` and `sources` (`ip6_mc_msfilter`), and
    /// leaves it for one that lets nothing in, as [`Self::leave6`] does:
    /// `EINVAL` for no group, no mode or as no member there, `ENODEV` for no
    /// device or one without IPv6.
    pub(crate) fn filter6(
        &self,
        memberships: &mut Vec<Member6>,
        asked: Membership6,
        mode: u32,
        sources: Vec<Ipv6Addr>,
        now: Option<u64>,
    ) -> Result<(), Errno> {
        let mode = Mode::read(mode).ok_or(Errno::EINVAL)?;
        let index = self.filtering_device6(asked, now)?;
        if mode == Mode::Include && sources.is_empty() {
            return self.leave6(memberships, asked);
        }
        let at = member6(memberships, asked, false).ok_or(Errno::EINVAL)?;
        let filter = &mut memberships[at].filter;
        self.with_groups6(index, |g| filter.set(g, asked.group, mode, sources));
        Ok(())
    }
    /// Whether a packet from `src` to the IPv6 group `group` in through the
    /// veth end `index` comes here: of a scope past the interface's and not
    /// from a loopback address (`ip6_rcv_core`), where a multicast route
    /// takes the group on that end (`ip6_route_input`) and the end is in it
    /// (`ip6_mc_input`).
    pub(crate) fn takes_group6(
        &self,
        index: i32,
        src: Ipv6Addr,
        group: Ipv6Addr,
        now: Option<u64>,
    ) -> bool {
        if scope6(group) <= 1 || src.is_loopback() || src.is_multicast() {
            return false;
        }
        let routed = self
            .addresses_at(now)
            .lookup6_flow(
                group,
                index.unsigned_abs(),
                &crate::interface::Flow6::default(),
            )
            .is_ok_and(|route| route.kind == crate::interface::Kind::Multicast);
        routed && self.has_ipv6(index) && self.in_group6(index, src, group, now)
    }
}
/// Which of `memberships` is of `group` on the device `index`.
fn member4(memberships: &[Member4], group: Ipv4Addr, index: i32) -> Option<usize> {
    memberships
        .iter()
        .position(|m| m.at.group == group && m.at.index == index)
}
/// Which of `memberships` is `asked`, on the device it names, or, for none
/// and `anywhere`, the newest of the group.
fn member6(memberships: &[Member6], asked: Membership6, anywhere: bool) -> Option<usize> {
    memberships.iter().position(|m| {
        m.at.group == asked.group && (anywhere && asked.index == 0 || m.at.index == asked.index)
    })
}
/// The filter of the one of `memberships` that is `asked`, on the very device
/// it names (`ip6_mc_msfget`): `EINVAL` for no group, `EADDRNOTAVAIL` as no
/// member there.
pub(crate) fn filter_of6(
    memberships: &[Member6],
    asked: Membership6,
) -> Result<&Filter<Ipv6Addr>, Errno> {
    if !asked.group.is_multicast() {
        return Err(Errno::EINVAL);
    }
    let at = member6(memberships, asked, false).ok_or(EADDRNOTAVAIL)?;
    Ok(&memberships[at].filter)
}
/// Whether `group` is one of the local network's, 224.0.0.0/24
/// (`ipv4_is_local_multicast`).
pub(crate) fn local_group(group: Ipv4Addr) -> bool {
    group.octets()[..3] == [224, 0, 0]
}
/// The Ethernet address an IPv4 group's packets go to (`ip_eth_mc_map`).
pub(crate) fn ethernet(group: IpAddr) -> [u8; 6] {
    match group {
        IpAddr::V4(group) => {
            let [_, b, c, d] = group.octets();
            [0x01, 0x00, 0x5e, b & 0x7f, c, d]
        }
        IpAddr::V6(group) => {
            let [.., a, b, c, d] = group.octets();
            [0x33, 0x33, a, b, c, d]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 1, 2, 3);
    const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const LO6: Ipv6Addr = Ipv6Addr::LOCALHOST;
    fn asked(index: i32) -> Membership {
        Membership {
            group: GROUP,
            address: Ipv4Addr::UNSPECIFIED,
            index,
        }
    }

    #[test]
    fn a_device_leaves_with_its_last_user() {
        let mut groups = Groups::default();
        let any = Filter::new(Mode::Exclude);
        assert!(groups.join(GROUP, Mode::Exclude, 7));
        assert!(!groups.join(GROUP, Mode::Exclude, 8));
        assert_eq!(groups.listed().collect::<Vec<_>>(), [(GROUP, 2, 7)]);
        assert_eq!(groups.leave(GROUP, &any), None);
        assert!(groups.takes(GROUP, None));
        assert_eq!(groups.leave(GROUP, &any), Some(7));
        assert!(!groups.takes(GROUP, None));
        // One never joined, nothing.
        assert_eq!(groups.leave(GROUP, &any), None);
        groups.add(GROUP, Mode::Include, &[GROUP], false);
        groups.remove(GROUP, Mode::Include, &[GROUP], false);
        assert_eq!(groups, Groups::default());
    }

    #[test]
    fn a_device_filters_as_its_memberships_do() {
        let [a, b] = [1, 2].map(|last| Ipv4Addr::new(10, 0, 0, last));
        let mut groups = Groups::default();
        let mut one = Filter::new(Mode::Include);
        groups.join(GROUP, Mode::Include, 0);
        let takes = |groups: &Groups<_>| [a, b].map(|s| groups.takes(GROUP, Some(s)));
        assert_eq!(takes(&groups), [false, false]);
        assert!(groups.takes(GROUP, None));
        let add = (true, Mode::Include, 2);
        assert_eq!(one.change(&mut groups, GROUP, add, a), Ok(false));
        assert_eq!(takes(&groups), [true, false]);
        // Another that excludes one: the other comes.
        let mut other = Filter::new(Mode::Exclude);
        groups.join(GROUP, Mode::Exclude, 0);
        assert_eq!(takes(&groups), [true, true]);
        for (source, then) in [(b, [true, false]), (a, [true, false])] {
            let block = (true, Mode::Exclude, 2);
            assert_eq!(other.change(&mut groups, GROUP, block, source), Ok(false));
            assert_eq!(takes(&groups), then);
        }
        // Its last included source is not taken away.
        let drop = (false, Mode::Include, 2);
        assert_eq!(one.change(&mut groups, GROUP, drop, a), Ok(true));
        groups.leave(GROUP, &one);
        assert_eq!(takes(&groups), [false, false]);
        // As one with a list stays of its mode.
        let wrong = other.change(&mut groups, GROUP, add, a);
        assert_eq!(wrong, Err(Errno::EINVAL));
        other.set(&mut groups, GROUP, Mode::Include, vec![b, b]);
        assert_eq!(takes(&groups), [false, true]);
        assert!(other.allows(b) && !other.allows(a));
        assert_eq!(other.change(&mut groups, GROUP, add, a), Err(ENOBUFS));
        other.set(&mut groups, GROUP, Mode::Exclude, Vec::new());
        assert_eq!(takes(&groups), [true, true]);
        // With no list it becomes one of another.
        let gone = other.change(&mut groups, GROUP, drop, a);
        assert_eq!(gone, Err(EADDRNOTAVAIL));
        assert_eq!(takes(&groups), [false, false]);
        assert_eq!(other.change(&mut groups, GROUP, add, a), Ok(false));
        let again = other.change(&mut groups, GROUP, add, a);
        assert_eq!(again, Err(EADDRNOTAVAIL));
        groups.leave(GROUP, &other);
        assert_eq!(groups, Groups::default());
    }

    #[test]
    fn sockets_join_and_leave_on_lo() {
        let network = Network::new(crate::inet::NetworkPolicy::default());
        assert!(network.in_group4(1, LO, ALL_HOSTS));
        let mut mine = Vec::new();
        assert_eq!(
            network.join4(&mut mine, asked(1), Mode::Exclude, None),
            Ok(())
        );
        assert_eq!(
            network.join4(&mut mine, asked(1), Mode::Exclude, None),
            Err(EADDRINUSE)
        );
        assert_eq!(
            network.join4(&mut mine, asked(9), Mode::Exclude, None),
            Err(ENODEV)
        );
        // By the group's route: there is none.
        assert_eq!(
            network.join4(&mut mine, asked(0), Mode::Exclude, None),
            Err(ENODEV)
        );
        let unicast = Membership {
            group: Ipv4Addr::LOCALHOST,
            ..asked(1)
        };
        assert_eq!(
            network.join4(&mut mine, unicast, Mode::Exclude, None),
            Err(Errno::EINVAL)
        );
        let to = (LO, GROUP);
        assert!(allows(&mine, false, to, 1) && !allows(&mine, false, to, 2));
        assert!(allows(&mine, true, to, 2));
        assert_eq!(network.leave4(&mut mine, asked(0), None), Err(ENODEV));
        assert_eq!(
            network.leave4(&mut mine, asked(9), None),
            Err(EADDRNOTAVAIL)
        );
        assert!(network.in_group4(1, LO, GROUP));
        // By the address of the device.
        let by_address = Membership {
            address: Ipv4Addr::LOCALHOST,
            ..asked(0)
        };
        assert_eq!(network.leave4(&mut mine, by_address, None), Ok(()));
        assert!(mine.is_empty() && !network.in_group4(1, LO, GROUP));
        for last in 0..MAX_MEMBERSHIPS as u8 {
            let group = Membership {
                group: Ipv4Addr::new(239, 0, 0, last),
                ..asked(1)
            };
            assert_eq!(network.join4(&mut mine, group, Mode::Exclude, None), Ok(()));
        }
        assert_eq!(
            network.join4(&mut mine, asked(1), Mode::Exclude, None),
            Err(ENOBUFS)
        );
        network.drop4(&mine);
        assert!(!network.in_group4(1, LO, Ipv4Addr::new(239, 0, 0, 0)));
    }

    #[test]
    fn a_device_tells_of_groups_joined_anew_and_left_for_good() {
        let network = Network::new(crate::inet::NetworkPolicy::default());
        let (mut mine, mut theirs) = (Vec::new(), Vec::new());
        let now = Some(5);
        network
            .join4(&mut mine, asked(1), Mode::Exclude, now)
            .unwrap();
        network
            .join4(&mut theirs, asked(1), Mode::Exclude, Some(6))
            .unwrap();
        let joined = Told4 {
            index: 1,
            group: GROUP,
            joined: true,
            created: 5,
        };
        assert_eq!(network.groups_told4(), [joined]);
        let listed = |network: &Network| {
            let devices = network.devices();
            devices
                .by_index(1)
                .unwrap()
                .groups4
                .listed()
                .collect::<Vec<_>>()
        };
        // The newest first, after the all-hosts group lo joined.
        assert_eq!(listed(&network), [(GROUP, 2, 5), (ALL_HOSTS, 1, 0)]);
        network.leave4(&mut mine, asked(1), now).unwrap();
        assert_eq!(network.groups_told4(), []);
        network.drop4(&theirs);
        let left = Told4 {
            joined: false,
            ..joined
        };
        assert_eq!(network.groups_told4(), [left]);
        assert_eq!(left.users(), 0);
        // lo itself, down and up.
        network.change_group4(1, ALL_HOSTS, false, 9);
        network.change_group4(1, ALL_HOSTS, true, 9);
        let told: Vec<_> = network
            .groups_told4()
            .iter()
            .map(|t| (t.joined, t.created))
            .collect();
        assert_eq!(told, [(false, 0), (true, 9)]);
    }

    #[test]
    fn ipv6_sockets_join_and_leave_on_lo() {
        let network = Network::new(crate::inet::NetworkPolicy::default());
        let nodes: Ipv6Addr = "ff02::1".parse().unwrap();
        let asked = |group: &str, index| Membership6 {
            group: group.parse().unwrap(),
            index,
        };
        let mut mine = Vec::new();
        assert!(network.in_group6(1, LO6, nodes, None));
        // No member of a group the device is in.
        assert_eq!(
            network.leave6(&mut mine, asked("ff02::1", 1)),
            Err(EADDRNOTAVAIL)
        );
        assert_eq!(
            network.join6(&mut mine, asked("ff02::1", 1), Mode::Exclude, None),
            Ok(())
        );
        assert_eq!(network.leave6(&mut mine, asked("ff02::1", 0)), Ok(()));
        assert!(network.in_group6(1, LO6, nodes, None));
        let group = asked("ff05::7", 1);
        assert_eq!(network.join6(&mut mine, group, Mode::Exclude, None), Ok(()));
        for index in [0, 1] {
            let again = Membership6 { index, ..group };
            assert_eq!(
                network.join6(&mut mine, again, Mode::Exclude, None),
                Err(EADDRINUSE)
            );
        }
        assert_eq!(
            network.join6(&mut mine, asked("ff05::7", 9), Mode::Exclude, None),
            Err(ENODEV)
        );
        assert_eq!(
            network.join6(&mut mine, asked("::1", 1), Mode::Exclude, None),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            network.leave6(&mut mine, asked("::1", 1)),
            Err(Errno::EINVAL)
        );
        assert!(network.in_group6(1, LO6, group.group, None));
        assert!(allows6(&mine, false, (LO6, group.group)));
        assert!(!allows6(&mine, false, (LO6, nodes)));
        network.drop6(&mine);
        assert!(!network.in_group6(1, LO6, group.group, None));
        // A loopback has no solicited-node nor all-routers group.
        for other in ["ff02::2", "ff02::1:ff00:1", "ff05::1", "ff02::1:0:1"] {
            assert!(!network.in_group6(1, LO6, other.parse().unwrap(), None));
        }
        assert_eq!(scope6("ff15::1".parse().unwrap()), 5);
    }

    #[test]
    fn memberships_read_both_layouts() {
        let mreqn = [239, 1, 2, 3, 10, 0, 0, 1, 7, 0, 0, 0];
        let m = Membership::read(&mreqn);
        assert_eq!(
            (m.group, m.address, m.index),
            (GROUP, Ipv4Addr::new(10, 0, 0, 1), 7)
        );
        assert_eq!(Membership::read(&mreqn[..8]).index, 0);
    }

    #[test]
    fn groups_map_to_ethernet() {
        let of = |ip: &str| ethernet(ip.parse().unwrap());
        assert_eq!(of("239.129.2.3"), [1, 0, 0x5e, 1, 2, 3]);
        assert_eq!(of("ff02::1:ff00:a"), [0x33, 0x33, 0xff, 0, 0, 0xa]);
    }
}
