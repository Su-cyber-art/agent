//! Release names and executable headers. Keep in sync with the agent repository.
pub fn asset(os: &str, arch: &str) -> Option<String> {
    if !matches!(arch, "x86_64" | "aarch64") {
        return None;
    }
    let suffix = match os {
        "linux" => "unknown-linux-musl",
        "windows" => "pc-windows-msvc.exe",
        "macos" => "apple-darwin",
        _ => return None,
    };
    Some(format!("monitor-agent-{arch}-{suffix}"))
}

pub fn built_for(binary: &[u8], os: &str, arch: &str) -> bool {
    if binary.len() < 64 || asset(os, arch).is_none() {
        return false;
    }
    let arm = arch == "aarch64";
    match os {
        "linux" => {
            binary.starts_with(b"\x7fELF\x02\x01")
                && binary.get(18..20) == Some((if arm { 183u16 } else { 62 }).to_le_bytes().as_slice())
        }
        "macos" => {
            binary.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
                && binary.get(4..8)
                    == Some((if arm { 0x0100_000cu32 } else { 0x0100_0007 }).to_le_bytes().as_slice())
                && binary.get(12..16) == Some(2u32.to_le_bytes().as_slice())
        }
        "windows" => {
            if !binary.starts_with(b"MZ") {
                return false;
            }
            let Some(offset) = binary.get(60..64) else { return false };
            let offset = u32::from_le_bytes(offset.try_into().unwrap()) as usize;
            let Some(end) = offset.checked_add(26) else { return false };
            let Some(pe) = binary.get(offset..end) else { return false };
            pe.starts_with(b"PE\0\0")
                && pe[4..6] == (if arm { 0xaa64u16 } else { 0x8664 }).to_le_bytes()
                && pe[24..26] == 0x020bu16.to_le_bytes()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_but_wrong_platform_or_architecture_must_be_refused() {
        for os in ["linux", "macos", "windows"] {
            for arch in ["x86_64", "aarch64"] {
                let arm = arch == "aarch64";
                let mut bytes = vec![0u8; 128];
                match os {
                    "linux" => {
                        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
                        bytes[18..20].copy_from_slice(&(if arm { 183u16 } else { 62 }).to_le_bytes());
                    }
                    "macos" => {
                        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
                        bytes[4..8]
                            .copy_from_slice(&(if arm { 0x0100_000cu32 } else { 0x0100_0007 }).to_le_bytes());
                        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
                    }
                    _ => {
                        bytes[..2].copy_from_slice(b"MZ");
                        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
                        bytes[64..68].copy_from_slice(b"PE\0\0");
                        bytes[68..70].copy_from_slice(&(if arm { 0xaa64u16 } else { 0x8664 }).to_le_bytes());
                        bytes[88..90].copy_from_slice(&0x020bu16.to_le_bytes());
                    }
                }
                assert!(built_for(&bytes, os, arch));
                assert!(!built_for(&bytes, os, if arm { "x86_64" } else { "aarch64" }));
                for other in ["linux", "macos", "windows"].into_iter().filter(|other| *other != os) {
                    assert!(!built_for(&bytes, other, arch));
                }
                for len in 0..20 {
                    assert!(!built_for(&bytes[..len], os, arch));
                }
            }
        }
        assert!(asset("../windows", "x86_64").is_none());
        assert!(asset("windows", "../../file").is_none());
    }
}
