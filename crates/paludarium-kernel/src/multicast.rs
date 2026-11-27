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
pub(crate) type Counts = [u32; 2];

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
    /// Whether its device has it in its filter (`MAF_LOADED`): from when
    /// it is joined or its device's IPv6 comes up (`ipv6_mc_up`) until that
    /// goes down (`ipv6_mc_down`).
    loaded: bool,
    modes: Counts,
    sources: Vec<(A, Counts)>,
}
/// The groups a device has joined (`in_dev->mc_list`, `idev->mc_list`), the
/// newest first: by sockets, and by the device itself.
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
                        loaded: true,
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
    /// (`in_dev_dump_ifmcaddr`, `in6_dump_addrs`).
    pub(crate) fn listed(&self) -> impl Iterator<Item = (A, u32, u64)> + '_ {
        self.list.iter().map(|g| (g.group, g.users, g.created))
    }
    /// Each group, the newest first, with its users and whether it is
    /// loaded (`/proc/net/igmp6`).
    pub(crate) fn loaded(&self) -> impl Iterator<Item = (A, u32, bool)> + '_ {
        self.list.iter().map(|g| (g.group, g.users, g.loaded))
    }
    /// Its device's IPv6 comes up, or goes down, for every group
    /// (`ipv6_mc_up`, `ipv6_mc_down`).
    fn load(&mut self, up: bool) {
        for g in &mut self.list {
            g.loaded = up;
        }
    }
    /// Every group goes, without a word (`ipv6_mc_destroy_dev`'s last).
    fn clear(&mut self) {
        self.list.clear();
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
    /// The groups, the newest first, each with its users and its sources,
    /// those first named first, by how many memberships of each mode name
    /// them (`/proc/net/igmp` and `mcfilter`).
    pub(crate) fn shown(&self) -> impl Iterator<Item = (A, u32, &[(A, Counts)])> {
        self.list
            .iter()
            .map(|g| (g.group, g.users, g.sources.as_slice()))
    }
}
/// A change of a device's groups that netlink tells of
/// (`inet_ifmcaddr_notify`, `inet6_ifmcaddr_notify`): a group the device
/// `index` has joined anew, of its one user, or left for good, of none, and
/// when it was joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Told<A> {
    pub index: i32,
    pub group: A,
    pub joined: bool,
    pub created: u64,
}
pub(crate) type Told4 = Told<Ipv4Addr>;
pub(crate) type Told6 = Told<Ipv6Addr>;
impl<A> Told<A> {
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
/// A change of a device's own IPv6 groups that its addresses and their
/// device's state make, kept in their order for [`Network::sync6`]: the
/// solicited-node group of an address joined at a time
/// (`addrconf_join_solict`) or left at one (`addrconf_leave_solict`),
/// reported unless the device is going down; the device's IPv6 coming up
/// at a time (`ipv6_mc_up`) or going down (`ipv6_mc_down`); and the
/// duplicate address detection of a veth end's only link-local address
/// ending at a time (`addrconf_dad_completed`), as it reports its groups
/// again (`ipv6_mc_dad_complete`) and, unless it forwards, solicits
/// routers (`ndisc_send_rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change6 {
    Join(i32, Ipv6Addr, u64),
    Leave(i32, Ipv6Addr, u64, bool),
    Up(i32, u64),
    Down(i32),
    Done(i32, u64),
}
/// A packet the kernel sends of itself, an MLD report or a router
/// solicitation: through the device of the index, to the group, at the
/// time.
pub(crate) type Send6 = (i32, Ipv6Addr, u64);
/// The group MLDv2 reports go to, of all MLDv2-capable routers
/// (`mld2_all_mcr`, `ff02::16`).
pub(crate) const REPORTS6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
/// Whether a device reports its membership of `group`: not of the
/// link-local all-nodes group, nor of one of a scope below the link's
/// (`MAF_NOREPORT`).
fn reported6(group: Ipv6Addr) -> bool {
    scope6(group) >= 2 && group != NODES6[1]
}
/// The interface-local and link-local all-nodes groups, `ff01::1` and
/// `ff02::1`.
const NODES6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
];
/// The link-local, interface-local and site-local all-routers groups, in
/// the order a device that forwards joins them (`dev_forward_change`).
const ROUTERS6: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
    Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 2),
    Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 2),
];
/// The IPv6 groups a device comes to IPv6 with at `now` (`ipv6_add_dev`):
/// the interface-local all-nodes group, then the link-local one.
pub(crate) fn all_nodes(now: u64) -> Groups<Ipv6Addr> {
    let mut groups = Groups::default();
    for group in NODES6 {
        groups.join(group, Mode::Exclude, now);
    }
    groups
}
/// The solicited-node group of `address` (`addrconf_addr_solict_mult`).
pub(crate) fn solicited(address: Ipv6Addr) -> Ipv6Addr {
    let o = address.octets();
    Ipv6Addr::from([
        0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, o[13], o[14], o[15],
    ])
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
    /// comes to it from `source` (`ipv6_chk_mcast_addr`), with its filters
    /// ([`Groups::takes`]).
    pub(crate) fn in_group6(&self, index: i32, source: Ipv6Addr, group: Ipv6Addr) -> bool {
        self.sync6();
        let source = (!source.is_unspecified()).then_some(source);
        self.devices()
            .groups6_of(index)
            .is_some_and(|(groups, _)| groups.takes(group, source))
    }
    /// Whether the device `index` has IPv6 at all (`in6_dev_get`): not a
    /// veth end of an MTU below 1280.
    fn has_ipv6(&self, index: i32) -> bool {
        self.devices().groups6_of(index).is_some()
    }
    /// Does `change` with the IPv6 groups of the device `index`, or with none
    /// while it is gone.
    fn with_groups6<R>(&self, index: i32, change: impl FnOnce(&mut Groups<Ipv6Addr>) -> R) -> R {
        self.sync6();
        match self.devices().by_index_mut(index) {
            Some(device) => change(&mut device.groups6),
            None => change(&mut Groups::default()),
        }
    }
    /// Makes the changes of the devices' own IPv6 groups that their
    /// addresses and states have queued ([`crate::multicast::Change6`]), in
    /// their order, before any other change or look at them; kept for
    /// netlink to tell of.
    pub(crate) fn sync6(&self) {
        let changes = core::mem::take(&mut self.addresses().changes6);
        if changes.is_empty() {
            return;
        }
        let lo_up = self.is_up();
        let mut sends = Vec::new();
        {
            let mut devices = self.devices();
            for change in changes {
                apply6(change, &mut devices, None, lo_up, &mut sends);
            }
        }
        self.send6(sends);
    }
    /// [`Self::sync6`], with `device` out of the namespace: the changes of
    /// it are made to it, and what they tell of given back; it sends
    /// nothing, as it is going.
    pub(crate) fn sync6_out(&self, device: &mut crate::netdev::Device) -> Vec<Told6> {
        let changes = core::mem::take(&mut self.addresses().changes6);
        let lo_up = self.is_up();
        let mut told = Vec::new();
        let mut sends = Vec::new();
        {
            let mut devices = self.devices();
            for change in changes {
                apply6(
                    change,
                    &mut devices,
                    Some((device, &mut told)),
                    lo_up,
                    &mut sends,
                );
            }
        }
        self.send6(sends);
        told
    }
    /// What the kernel sends of itself goes out, making the neighbours of
    /// the groups it goes to ([`crate::interface::Addresses::send6`]).
    fn send6(&self, sends: Vec<Send6>) {
        if sends.is_empty() {
            return;
        }
        let mut addresses = self.addresses();
        for (index, to, at) in sends {
            addresses.send6(index, to, at);
        }
    }
    /// Whether the device `index` is up (`IFF_UP`).
    fn up6(&self, index: i32) -> bool {
        if index == crate::netdev::LOOPBACK_INDEX {
            return self.is_up();
        }
        self.devices()
            .by_index(index)
            .and_then(|d| d.veth.as_ref())
            .is_some_and(|v| v.up)
    }
    /// The device `index` reports at `now` that it has joined `group` anew
    /// or left it for good (`igmp6_group_added`, `igmp6_leave_group`), as
    /// it does up, for a group it reports: an MLDv2 report to
    /// [`REPORTS6`].
    fn report6(&self, index: i32, group: Ipv6Addr, now: u64) {
        if reported6(group) && self.up6(index) {
            self.send6(vec![(index, REPORTS6, now)]);
        }
    }
    /// What the IPv6 groups' changes since the last call were, in their
    /// order, for netlink to tell of.
    pub(crate) fn groups_told6(&self) -> Vec<Told6> {
        self.sync6();
        core::mem::take(&mut self.devices().told6)
    }
    /// The device `index` comes to IPv6 at `now` (`ipv6_add_dev`): it joins
    /// the all-nodes groups, and, a veth end that forwards, the link-local
    /// all-routers group, a loopback having no multicast (`IFF_MULTICAST`).
    pub(crate) fn register6(&self, index: i32, now: u64) {
        self.sync6();
        let mut devices = self.devices();
        let Some(routes) = devices
            .by_index(index)
            .map(|d| d.veth.is_some() && d.conf6.forwarding != 0)
        else {
            return;
        };
        for group in NODES6 {
            join_in6(&mut devices, index, group, Mode::Exclude, now);
        }
        if routes {
            join_in6(&mut devices, index, ROUTERS6[0], Mode::Exclude, now);
        }
    }
    /// The device `index` goes from IPv6 ([`destroy6`]), kept for netlink
    /// to tell of.
    pub(crate) fn destroy6(&self, index: i32) {
        self.sync6();
        let mut devices = self.devices();
        let Some(device) = devices.by_index_mut(index) else {
            return;
        };
        let told = destroy6(device);
        devices.told6.extend(told);
    }
    /// The veth end `index` comes to forward IPv6 at `now`, or no longer
    /// does (`dev_forward_change`): it joins the all-routers groups, or
    /// leaves them.
    pub(crate) fn forward6(&self, index: i32, on: bool, now: u64) {
        self.sync6();
        let mut changed = Vec::new();
        {
            let mut devices = self.devices();
            if !devices.by_index(index).is_some_and(|d| d.veth.is_some()) {
                return;
            }
            let filter = Filter::new(Mode::Exclude);
            for group in ROUTERS6 {
                let anew = if on {
                    join_in6(&mut devices, index, group, Mode::Exclude, now)
                } else {
                    leave_in6(&mut devices, index, group, &filter)
                };
                if anew {
                    changed.push(group);
                }
            }
        }
        if let Some(&group) = changed.iter().find(|&&g| reported6(g)) {
            self.report6(index, group, now);
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
        self.sync6();
        let now = now.unwrap_or_else(|| self.addresses().seen());
        if join_in6(&mut self.devices(), index, asked.group, mode, now) {
            self.report6(index, asked.group, now);
        }
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
        self.sync6();
        let (index, group) = (left.at.index, left.at.group);
        if leave_in6(&mut self.devices(), index, group, &left.filter) {
            let now = self.addresses().seen();
            self.report6(index, group, now);
        }
        Ok(())
    }
    /// A socket of `memberships` that goes leaves them all
    /// (`__ipv6_sock_mc_close`).
    pub(crate) fn drop6(&self, memberships: &[Member6]) {
        self.sync6();
        let gone: Vec<(i32, Ipv6Addr)> = {
            let mut devices = self.devices();
            memberships
                .iter()
                .filter(|m| leave_in6(&mut devices, m.at.index, m.at.group, &m.filter))
                .map(|m| (m.at.index, m.at.group))
                .collect()
        };
        let now = self.addresses().seen();
        for (index, group) in gone {
            self.report6(index, group, now);
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
        routed && self.has_ipv6(index) && self.in_group6(index, src, group)
    }
}
/// Makes `change` in `devices`, or in `out`, a device out of them, with
/// what it tells of, if it is of that one; and what a device up (the
/// loopback as `lo_up` says) sends of it to `sends`: an MLDv2 report of a
/// group it reports joined anew or left for good, of its groups as its
/// IPv6 comes up or its duplicate address detection ends where it has one
/// it reports, and then a router solicitation unless it forwards.
fn apply6(
    change: Change6,
    devices: &mut crate::netdev::Devices,
    out: Option<(&mut crate::netdev::Device, &mut Vec<Told6>)>,
    lo_up: bool,
    sends: &mut Vec<Send6>,
) {
    let index = match change {
        Change6::Join(index, ..)
        | Change6::Leave(index, ..)
        | Change6::Up(index, _)
        | Change6::Down(index)
        | Change6::Done(index, _) => index,
    };
    let out_of = out
        .as_ref()
        .is_some_and(|(device, _)| device.index == index);
    let (up, routes) = match devices.by_index(index) {
        _ if out_of => (false, false),
        Some(d) => match &d.veth {
            Some(v) => (v.up, d.conf6.forwarding != 0),
            None => (lo_up, false),
        },
        None => (false, false),
    };
    let (groups, told) = match out {
        Some((device, told)) if device.index == index => {
            if device.veth.as_ref().is_some_and(|v| v.mtu < 1280) {
                return;
            }
            (&mut device.groups6, told)
        }
        _ => match devices.groups6_of(index) {
            Some(found) => found,
            None => return,
        },
    };
    let reports = |groups: &Groups<Ipv6Addr>| groups.loaded().any(|(g, ..)| reported6(g));
    match change {
        Change6::Join(index, group, now) => {
            if groups.join(group, Mode::Exclude, now) {
                told.push(Told6 {
                    index,
                    group,
                    joined: true,
                    created: now,
                });
                if up && reported6(group) {
                    sends.push((index, REPORTS6, now));
                }
            }
        }
        Change6::Leave(index, group, now, report) => {
            if let Some(created) = groups.leave(group, &Filter::new(Mode::Exclude)) {
                told.push(Told6 {
                    index,
                    group,
                    joined: false,
                    created,
                });
                if report && up && reported6(group) {
                    sends.push((index, REPORTS6, now));
                }
            }
        }
        Change6::Up(index, now) => {
            groups.load(true);
            if up && reports(groups) {
                sends.push((index, REPORTS6, now));
            }
        }
        Change6::Down(_) => groups.load(false),
        Change6::Done(index, now) => {
            if up {
                if reports(groups) {
                    sends.push((index, REPORTS6, now));
                }
                if !routes {
                    sends.push((index, ROUTERS6[0], now));
                }
            }
        }
    }
}
/// `device`, out of its namespace, goes from IPv6 (`ipv6_mc_destroy_dev`),
/// after its addresses: it leaves the link-local all-nodes group, and, as
/// it forwards, the all-routers one; the rest go without a word. What it
/// tells of.
pub(crate) fn destroy6(device: &mut crate::netdev::Device) -> Vec<Told6> {
    let mut told = Vec::new();
    let index = device.index;
    let routes = device.conf6.forwarding != 0;
    let filter = Filter::new(Mode::Exclude);
    for group in [NODES6[1], ROUTERS6[0]]
        .into_iter()
        .take(1 + usize::from(routes))
    {
        if let Some(created) = device.groups6.leave(group, &filter) {
            told.push(Told6 {
                index,
                group,
                joined: false,
                created,
            });
        }
    }
    device.groups6.clear();
    told
}
/// The device `index` of `devices` joins the IPv6 `group` at `now`, kept
/// for netlink to tell of as it does it anew: whether it does.
fn join_in6(
    devices: &mut crate::netdev::Devices,
    index: i32,
    group: Ipv6Addr,
    mode: Mode,
    now: u64,
) -> bool {
    let Some((groups, told)) = devices.groups6_of(index) else {
        return false;
    };
    if !groups.join(group, mode, now) {
        return false;
    }
    told.push(Told6 {
        index,
        group,
        joined: true,
        created: now,
    });
    true
}
/// It leaves `group` once, as a membership of `filter` does, kept for
/// netlink to tell of as it leaves it for good: whether it does.
fn leave_in6(
    devices: &mut crate::netdev::Devices,
    index: i32,
    group: Ipv6Addr,
    filter: &Filter<Ipv6Addr>,
) -> bool {
    let Some((groups, told)) = devices.groups6_of(index) else {
        return false;
    };
    let Some(created) = groups.leave(group, filter) else {
        return false;
    };
    told.push(Told6 {
        index,
        group,
        joined: false,
        created,
    });
    true
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
    fn a_device_keeps_its_own_ipv6_groups_in_order_with_the_sockets() {
        use crate::netdev::{Conf4, Conf6, Device};
        let network = Network::isolated(crate::users::first());
        let va = Device::veth(
            1000,
            b"va".to_vec(),
            [2, 0, 0, 0, 0, 0xa],
            1500,
            (Conf4::default(), Conf6::default()),
        );
        network.devices().add(va, true);
        network.register6(1000, 1);
        let node = |id: u16| Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, id);
        let nodes1 = Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1);
        let told = |network: &Network| {
            network
                .groups_told6()
                .iter()
                .map(|t| (t.index, t.group, t.joined))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            told(&network),
            [(1000, nodes1, true), (1000, node(1), true)]
        );
        // An address's solicited-node group, once for each address that has
        // it, made as it is next looked at.
        let address: Ipv6Addr = "2001:db8::a".parse().unwrap();
        let solicited = super::solicited(address);
        assert_eq!(solicited, "ff02::1:ff00:a".parse::<Ipv6Addr>().unwrap());
        network.addresses().changes6.extend([
            Change6::Up(1000, 2),
            Change6::Join(1000, solicited, 2),
            Change6::Join(1000, solicited, 3),
        ]);
        let mut mine = Vec::new();
        let ff15 = Membership6 {
            group: "ff15::1".parse().unwrap(),
            index: 1000,
        };
        network
            .join6(&mut mine, ff15, Mode::Exclude, Some(4))
            .unwrap();
        let listed = |network: &Network| {
            network.sync6();
            network
                .devices()
                .by_index(1000)
                .unwrap()
                .groups6
                .loaded()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            listed(&network),
            [
                (ff15.group, 1, true),
                (solicited, 2, true),
                (node(1), 1, true),
                (nodes1, 1, true)
            ]
        );
        assert_eq!(
            told(&network),
            [(1000, solicited, true), (1000, ff15.group, true)]
        );
        // Forwarding, then down, then gone.
        network.forward6(1000, true, 5);
        assert_eq!(told(&network).len(), 3);
        network.forward6(1000, false, 6);
        network.addresses().changes6.extend([
            Change6::Leave(1000, solicited, 6, true),
            Change6::Leave(1000, solicited, 6, true),
            Change6::Down(1000),
        ]);
        assert!(listed(&network).iter().all(|&(_, _, loaded)| !loaded));
        assert_eq!(told(&network).len(), 4);
        network.destroy6(1000);
        assert_eq!(told(&network), [(1000, node(1), false)]);
        assert!(listed(&network).is_empty());
        assert!(!network.in_group6(1000, Ipv6Addr::UNSPECIFIED, ff15.group));
    }

    #[test]
    fn a_device_up_reports_its_groups_and_solicits_routers() {
        use crate::netdev::{Conf4, Conf6, Device};
        let network = Network::isolated(crate::users::first());
        let va = Device::veth(
            1000,
            b"va".to_vec(),
            [2, 0, 0, 0, 0, 0xa],
            1500,
            (Conf4::default(), Conf6::default()),
        );
        network.devices().add(va, true);
        network.register6(1000, 1);
        let neighbours = |network: &Network| {
            network.sync6();
            network
                .addresses()
                .neighbours()
                .iter()
                .map(|n| (n.index, n.ip, n.made))
                .collect::<Vec<_>>()
        };
        let solicited = super::solicited("fe80::ff:fe00:a".parse().unwrap());
        // Down, it reports nothing.
        network
            .addresses()
            .changes6
            .push(Change6::Join(1000, solicited, 2));
        assert!(neighbours(&network).is_empty());
        if let Some(v) = network.devices().by_index_mut(1000).unwrap().veth.as_mut() {
            v.up = true;
        }
        // Up, it reports the group it has and reports, and again as its
        // only link-local address is done, then solicits routers.
        network
            .addresses()
            .changes6
            .extend([Change6::Up(1000, 3), Change6::Done(1000, 4)]);
        let reports = IpAddr::V6(REPORTS6);
        let routers = IpAddr::V6(ROUTERS6[0]);
        assert_eq!(
            neighbours(&network),
            [(1000, reports, 3), (1000, routers, 4)]
        );
        // A group it reports, joined anew or left for good, is reported;
        // the link-local all-nodes one never.
        let gone = |network: &Network| {
            let _ = network
                .addresses()
                .delete_neighbour(1000, reports, 5)
                .unwrap();
        };
        gone(&network);
        let mut mine = Vec::new();
        let all = Membership6 {
            group: NODES6[1],
            index: 1000,
        };
        network
            .join6(&mut mine, all, Mode::Exclude, Some(5))
            .unwrap();
        assert_eq!(neighbours(&network), [(1000, routers, 4)]);
        let ff15 = Membership6 {
            group: "ff15::1".parse().unwrap(),
            index: 1000,
        };
        network
            .join6(&mut mine, ff15, Mode::Exclude, Some(6))
            .unwrap();
        assert_eq!(neighbours(&network)[1], (1000, reports, 6));
        gone(&network);
        // The setting changes first, as a write of `forwarding` makes it.
        network
            .devices()
            .by_index_mut(1000)
            .unwrap()
            .conf6
            .forwarding = 1;
        network.forward6(1000, true, 7);
        assert_eq!(neighbours(&network)[1], (1000, reports, 7));
        gone(&network);
        network.leave6(&mut mine, ff15).unwrap();
        assert_eq!(neighbours(&network).len(), 2);
        gone(&network);
        // Going down, it reports nothing; a device that forwards solicits
        // no router.
        network
            .addresses()
            .changes6
            .push(Change6::Leave(1000, solicited, 8, false));
        assert_eq!(neighbours(&network).len(), 1);
        let _ = network
            .addresses()
            .delete_neighbour(1000, routers, 9)
            .unwrap();
        network.addresses().changes6.push(Change6::Done(1000, 9));
        assert_eq!(neighbours(&network), [(1000, reports, 9)]);
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
        assert!(network.in_group6(1, LO6, nodes));
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
        assert!(network.in_group6(1, LO6, nodes));
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
        assert!(network.in_group6(1, LO6, group.group));
        assert!(allows6(&mine, false, (LO6, group.group)));
        assert!(!allows6(&mine, false, (LO6, nodes)));
        network.drop6(&mine);
        assert!(!network.in_group6(1, LO6, group.group));
        // A loopback has no solicited-node nor all-routers group.
        for other in ["ff02::2", "ff02::1:ff00:1", "ff05::1", "ff02::1:0:1"] {
            assert!(!network.in_group6(1, LO6, other.parse().unwrap()));
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
