//! Shared reporting fields; each platform supplies its own collector.
use serde::Serialize;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{hidden_mounts, shadowed_mounts, unreadable_mounts, Collector};
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod desktop;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use desktop::Collector;

#[derive(Serialize, PartialEq)]
pub struct Facts {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub virt: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub agent_version: String,
    /// The host's own addresses, public ones first. The hub sees
    /// only the family the agent connected over.
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Serialize)]
pub struct Metrics {
    /// Names the span over which `net_rx_total` and `net_tx_total` readings
    /// are comparable. The hub only tests it for equality, and a change makes
    /// it re-baseline rather than book the difference. It is the kernel's boot
    /// id, which changes when the counters restart at zero, then `/` and a
    /// digest of the interfaces summed: an interface joining the sum within one
    /// boot -- a reclassified device, a changed `--iface` -- would otherwise
    /// have its lifetime bytes booked as traffic.
    pub boot_id: String,
    /// The `--iface` this agent runs with, empty for the default rules. Shown
    /// by the panel, which reinstalls with it.
    pub iface: String,
    pub uptime: u64,
    pub cpu: f32,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    /// The counted interfaces' lifetime byte counters, summed. The hub
    /// accumulates these; the agent stores nothing and does not attempt to
    /// survive a reboot.
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub tcp: u32,
    pub udp: u32,
    pub procs: u32,
}

/// The traffic filter set by `--iface`: full interface names separated by
/// commas.
///
/// A plain entry makes the list the whole answer: nothing unlisted is counted.
/// Only the machine's owner knows which port faces the provider on a router,
/// where a forwarded byte crosses two real NICs, or whether a Proxmox host's
/// `vmbr0` alone should count. A listed name is counted whatever the built-in
/// rules say, since that is how `vmbr0` or `pppoe-wan` is chosen. An entry
/// starting with `-` removes that interface from what is counted otherwise,
/// which one batch command can apply across machines whose other NICs are named
/// differently. Exclusions win over inclusions.
#[derive(Default)]
pub struct Ifaces {
    spec: String,
    only: Vec<String>,
    skip: Vec<String>,
}

impl Ifaces {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let entries: Vec<&str> = spec.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        let mut ifaces = Self { spec: entries.join(","), ..Self::default() };
        for entry in entries {
            let (list, name) = match entry.strip_prefix('-') {
                Some(name) => (&mut ifaces.skip, name),
                None => (&mut ifaces.only, entry),
            };
            // Windows adapter names may contain spaces (for example Ethernet 2).
            if name.is_empty()
                || name.starts_with('-')
                || name.chars().any(|c| c.is_control() || (c.is_whitespace() && !cfg!(windows)))
            {
                return Err(format!(
                    "--iface: {entry:?} is not an interface name; give full names separated by commas"
                ));
            }
            list.push(name.to_owned());
        }
        Ok(ifaces)
    }
}

/// See [`Metrics::boot_id`]. The names are sorted, since /proc/net/dev lists a
/// recreated interface in a new position without the set having changed, and
/// hashed with FNV-1a, whose output no Rust release can alter.
///
/// ponytail: every change of the set costs the hub one interval on every
/// interface, including a freshly created one, whose counter starts at zero and
/// would have added correctly. Where counted interfaces come and go -- pods under
/// names no rule knows, pppN on a VPN server -- each event loses one interval.
/// Per-interface counters in the report, summed by the hub, would remove the
/// loss; an offset kept here would not, as it dies with the process and takes the
/// traffic of the downtime with it.
fn epoch<'a>(boot_id: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    // A newline cannot occur in an interface name, so no two sets join alike.
    let digest = names
        .join("\n")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
    format!("{boot_id}/{digest:016x}")
}

/// Globally routable. Excluded on the v4 side: RFC 1918, CGNAT (100.64/10),
/// loopback, link-local, 0/8, 192.0.0/24 (where 464XLAT places its CLAT),
/// 198.18/15 (the fake-IP range TUN-mode proxies such as Clash assign to
/// themselves), multicast and reserved. On the v6 side only 2000::/3 counts,
/// which leaves out ULA (fc00::/7), link-local and loopback.
///
/// The hub applies the same ranges to the addresses this agent reports; the two
/// lists are to be changed together.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xe000 == 0x2000,
    }
}
