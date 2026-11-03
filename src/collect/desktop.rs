//! Native Windows/macOS counters. Linux keeps its /proc accounting.
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sysinfo::{Disks, Networks, ProcessRefreshKind, ProcessesToUpdate, System};

use super::{epoch, is_public, Facts, Ifaces, Metrics};

pub struct Collector {
    ifaces: Ifaces,
    system: System,
    networks: Networks,
    disks: Disks,
    boot: String,
    previous: HashMap<String, (u64, u64)>,
    sampled: Option<Instant>,
}

impl Ifaces {
    fn counts(&self, name: &str) -> bool {
        if self.skip.iter().any(|n| n == name) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.iter().any(|n| n == name);
        }
        let name = name.to_lowercase();
        // "Local Area Connection" is a physical Windows adapter name.
        if name.strip_prefix("lo").is_some_and(|suffix| suffix.bytes().all(|c| c.is_ascii_digit())) {
            return false;
        }
        !["loopback", "utun", "awdl", "llw", "bridge", "veth", "vethernet", "tailscale", "tun", "tap"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }
}

impl Collector {
    pub fn new(ifaces: Ifaces) -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        Self {
            ifaces,
            system,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            boot: System::boot_time().to_string(),
            previous: HashMap::new(),
            sampled: None,
        }
    }

    pub fn counted_ifaces(&self) -> Vec<String> {
        self.networks.keys().filter(|name| self.ifaces.counts(name)).cloned().collect()
    }

    pub fn capacities(&self) -> [(&'static str, u64); 3] {
        [
            ("mem_total", self.system.total_memory()),
            ("swap_total", self.system.total_swap()),
            ("disk_total", self.disk_usage().0),
        ]
    }

    pub fn facts(&self) -> Facts {
        let addresses = if_addrs::get_if_addrs().unwrap_or_default();
        let best = |v6| {
            addresses
                .iter()
                .filter(|i| {
                    !i.is_loopback() && !i.is_link_local() && i.is_oper_up() && i.ip().is_ipv6() == v6
                })
                .min_by_key(|i| !is_public(i.ip()))
                .map_or_else(String::new, |i| i.ip().to_string())
        };
        Facts {
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            os: System::long_os_version().unwrap_or_else(|| std::env::consts::OS.into()),
            kernel: System::kernel_version().unwrap_or_default(),
            arch: std::env::consts::ARCH.into(),
            virt: String::new(),
            cpu_name: self.system.cpus().first().map_or_else(String::new, |cpu| cpu.brand().into()),
            cpu_cores: self.system.cpus().len() as u32,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            ipv4: best(false),
            ipv6: best(true),
        }
    }

    fn disk_usage(&self) -> (u64, u64) {
        let mut seen = HashSet::new();
        let has_data =
            self.disks.iter().any(|d| d.mount_point() == std::path::Path::new("/System/Volumes/Data"));
        self.disks
            .iter()
            .filter(|disk| {
                let mount = disk.mount_point();
                // macOS exposes the boot APFS container through several volumes.
                // Count its writable Data volume once, alongside external disks.
                let system_volume = mount.starts_with("/System/Volumes")
                    && mount != std::path::Path::new("/System/Volumes/Data");
                !(cfg!(target_os = "macos")
                    && (system_volume || (has_data && mount == std::path::Path::new("/"))))
                    && seen.insert(disk.mount_point())
            })
            .fold((0u64, 0u64), |(total, used), disk| {
                (
                    total.saturating_add(disk.total_space()),
                    used.saturating_add(disk.total_space().saturating_sub(disk.available_space())),
                )
            })
    }

    pub fn collect(&mut self) -> Metrics {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
        self.networks.refresh(true);
        self.disks.refresh(true);
        let now = Instant::now();
        let counted: HashMap<_, _> = self
            .networks
            .iter()
            .filter(|(name, _)| self.ifaces.counts(name))
            .map(|(name, data)| (name.clone(), (data.total_received(), data.total_transmitted())))
            .collect();
        let (rx, tx) =
            rates(&self.previous, &counted, self.sampled.map(|last| now.duration_since(last).as_secs_f64()));
        let (rx_total, tx_total) = counted
            .values()
            .fold((0u64, 0u64), |(rx, tx), (r, t)| (rx.saturating_add(*r), tx.saturating_add(*t)));
        let boot_id = epoch(&self.boot, counted.keys().map(String::as_str));
        self.previous = counted;
        self.sampled = Some(now);
        let (disk_total, disk_used) = self.disk_usage();
        let load = System::load_average();
        let (mut tcp, mut udp) = (0, 0);
        if let Ok(sockets) = netstat2::get_sockets_info(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        ) {
            for socket in sockets {
                match socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(_) => tcp += 1,
                    ProtocolSocketInfo::Udp(_) => udp += 1,
                }
            }
        }
        Metrics {
            boot_id,
            iface: self.ifaces.spec.clone(),
            uptime: System::uptime(),
            cpu: self.system.global_cpu_usage(),
            load: [load.one as f32, load.five as f32, load.fifteen as f32],
            mem_total: self.system.total_memory(),
            mem_used: self.system.used_memory(),
            swap_total: self.system.total_swap(),
            swap_used: self.system.used_swap(),
            disk_total,
            disk_used,
            net_rx_total: rx_total,
            net_tx_total: tx_total,
            net_rx: rx,
            net_tx: tx,
            tcp,
            udp,
            procs: self.system.processes().len() as u32,
        }
    }
}

fn rates(
    previous: &HashMap<String, (u64, u64)>,
    current: &HashMap<String, (u64, u64)>,
    seconds: Option<f64>,
) -> (u64, u64) {
    let Some(seconds) = seconds.filter(|s| *s > 0.0) else { return (0, 0) };
    let (rx, tx) = current
        .iter()
        .filter_map(|(name, (rx, tx))| {
            let (old_rx, old_tx) = previous.get(name)?;
            Some((rx.saturating_sub(*old_rx), tx.saturating_sub(*old_tx)))
        })
        .fold((0u64, 0u64), |(rx, tx), (r, t)| (rx.saturating_add(r), tx.saturating_add(t)));
    ((rx as f64 / seconds) as u64, (tx as f64 / seconds) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_changes_do_not_create_traffic_spikes() {
        let previous = HashMap::from([("en0".into(), (100, 200)), ("reset".into(), (900, 900))]);
        let current = HashMap::from([
            ("en0".into(), (140, 260)),
            ("reset".into(), (10, 10)),
            ("new".into(), (9000, 9000)),
        ]);
        assert_eq!(rates(&previous, &current, Some(2.0)), (20, 30));
        assert_eq!(rates(&previous, &current, None), (0, 0));
        assert_ne!(
            epoch("boot", previous.keys().map(String::as_str)),
            epoch("boot", current.keys().map(String::as_str))
        );
    }

    #[test]
    fn interface_overrides_and_exclusions_work() {
        let defaults = Ifaces::parse("").unwrap();
        assert!(defaults.counts("Ethernet 2") && defaults.counts("en0"));
        assert!(defaults.counts("Local Area Connection"));
        assert!(!defaults.counts("lo0"));
        assert!(!defaults.counts("utun0") && !defaults.counts("vEthernet (WSL)"));
        let explicit = Ifaces::parse("utun0,en0,-en0").unwrap();
        assert!(explicit.counts("utun0") && !explicit.counts("en0"));
        #[cfg(windows)]
        assert!(Ifaces::parse("Ethernet 2,-Wi-Fi").unwrap().counts("Ethernet 2"));
    }

    #[test]
    fn native_collection_reports_real_host_capacity() {
        let mut collector = Collector::new(Ifaces::default());
        let facts = collector.facts();
        let metrics = collector.collect();
        assert!(facts.cpu_cores > 0);
        assert!(metrics.mem_total > 0 && metrics.mem_used <= metrics.mem_total);
        assert!(metrics.disk_total > 0 && metrics.disk_used <= metrics.disk_total);
        assert!(metrics.uptime > 0 && metrics.procs > 0);
        assert!(!facts.hostname.is_empty() && !facts.os.is_empty());
    }
}
