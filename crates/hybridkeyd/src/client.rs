//! Works out which program is talking to the virtual key, by finding the
//! processes that hold its hidraw node open. Used to stay out of the way of
//! browsers that already do hybrid themselves (Chromium and friends), which
//! would otherwise show their own QR code next to ours.

use std::fs;
use std::path::{Path, PathBuf};

/// Executable names of browsers with their own hybrid support on Linux.
pub const DEFAULT_DEFER_TO: &[&str] = &[
    "chrome",
    "chromium",
    "brave",
    "msedge",
    "vivaldi-bin",
    "opera",
];

/// Executable base names of the processes that have our hidraw node open.
pub fn requesting_programs() -> Vec<String> {
    let uniq = hybridkey_uhid::device_uniq(current_uid());
    let Some(node) = our_hidraw_node(Path::new("/sys/class/hidraw"), &uniq) else {
        return Vec::new();
    };
    let own_pid = std::process::id().to_string();
    let mut programs = Vec::new();
    let Ok(procs) = fs::read_dir("/proc") else {
        return programs;
    };
    for proc in procs.flatten() {
        let pid = proc.file_name();
        let Some(pid) = pid
            .to_str()
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        // Other users' processes are unreadable, which is fine: only our own
        // session's processes can open the node anyway.
        let Ok(fds) = fs::read_dir(proc.path().join("fd")) else {
            continue;
        };
        let holds_node = fds
            .flatten()
            .any(|fd| fs::read_link(fd.path()).is_ok_and(|target| target == node));
        if holds_node {
            if let Some(name) = fs::read_link(proc.path().join("exe"))
                .ok()
                .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().into_owned()))
            {
                if !programs.contains(&name) {
                    programs.push(name);
                }
            }
        }
    }
    programs
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

fn our_hidraw_node(class_dir: &Path, uniq: &str) -> Option<PathBuf> {
    fs::read_dir(class_dir).ok()?.flatten().find_map(|entry| {
        let uevent = fs::read_to_string(entry.path().join("device/uevent")).ok()?;
        uevent
            .lines()
            .any(|line| line.strip_prefix("HID_UNIQ=") == Some(uniq))
            .then(|| Path::new("/dev").join(entry.file_name()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_node_by_uniq() {
        let dir = std::env::temp_dir().join(format!("hybridkey-test-{}", std::process::id()));
        for (name, uniq) in [("hidraw0", "hybridkey-1"), ("hidraw7", "hybridkey-1000")] {
            let device = dir.join(name).join("device");
            fs::create_dir_all(&device).unwrap();
            fs::write(
                device.join("uevent"),
                format!("HID_NAME=x\nHID_UNIQ={uniq}\n"),
            )
            .unwrap();
        }
        assert_eq!(
            our_hidraw_node(&dir, "hybridkey-1000"),
            Some(PathBuf::from("/dev/hidraw7"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
