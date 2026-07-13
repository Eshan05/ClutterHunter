use crate::scan::{ScanTarget, ScanTargetKind};

#[cfg(windows)]
pub fn scan_targets() -> Vec<ScanTarget> {
    use windows::{
        Win32::{
            Storage::FileSystem::{
                GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
                GetVolumeNameForVolumeMountPointW,
            },
            System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE},
        },
        core::PCWSTR,
    };

    let drive_mask = unsafe { GetLogicalDrives() };
    let system_drive = std::env::var("SystemDrive")
        .unwrap_or_else(|_| "C:".to_owned())
        .to_ascii_uppercase();
    let mut targets = Vec::new();

    for offset in 0..26u32 {
        if drive_mask & (1 << offset) == 0 {
            continue;
        }

        let letter = char::from_u32('A' as u32 + offset).unwrap_or('C');
        let display_path = format!("{letter}:\\");
        let path_wide = wide_null(&display_path);
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(path_wide.as_ptr())) };
        if drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE {
            continue;
        }

        let mut filesystem_buffer = [0u16; 32];
        let mut volume_label_buffer = [0u16; 261];
        let mut serial = 0u32;
        let volume_info = unsafe {
            GetVolumeInformationW(
                PCWSTR(path_wide.as_ptr()),
                Some(&mut volume_label_buffer),
                Some(&mut serial),
                None,
                None,
                Some(&mut filesystem_buffer),
            )
        };

        let filesystem = volume_info
            .as_ref()
            .ok()
            .map(|_| utf16_buffer_to_string(&filesystem_buffer))
            .filter(|value| !value.is_empty());

        let mut volume_name_buffer = [0u16; 50];
        let volume_id = unsafe {
            GetVolumeNameForVolumeMountPointW(PCWSTR(path_wide.as_ptr()), &mut volume_name_buffer)
        }
        .ok()
        .map(|_| utf16_buffer_to_string(&volume_name_buffer))
        .filter(|value| !value.is_empty());

        let mut available = 0u64;
        let mut total = 0u64;
        let disk_space = unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR(path_wide.as_ptr()),
                Some(&mut available),
                Some(&mut total),
                None,
            )
        };
        let (total_bytes, available_bytes) = if disk_space.is_ok() {
            (Some(total.to_string()), Some(available.to_string()))
        } else {
            (None, None)
        };

        let stable_id = volume_id
            .as_deref()
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| format!("volume-{serial:08x}-{letter}"));
        let fast_scan_available = filesystem
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("NTFS"));

        targets.push(ScanTarget {
            id: stable_id,
            kind: ScanTargetKind::Volume,
            display_path,
            filesystem,
            volume_id,
            total_bytes,
            available_bytes,
            fast_scan_available,
        });
    }

    targets.sort_by_key(|target| {
        let drive = target
            .display_path
            .trim_end_matches('\\')
            .to_ascii_uppercase();
        (drive != system_drive, drive)
    });

    if targets.is_empty() {
        targets.push(fallback_system_target());
    }

    targets
}

#[cfg(not(windows))]
pub fn scan_targets() -> Vec<ScanTarget> {
    vec![fallback_system_target()]
}

fn fallback_system_target() -> ScanTarget {
    let display_path = if cfg!(windows) {
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        format!("{system_drive}\\")
    } else {
        "/".to_owned()
    };

    ScanTarget {
        id: "system-volume".to_owned(),
        kind: ScanTargetKind::Volume,
        display_path,
        filesystem: None,
        volume_id: None,
        total_bytes: None,
        available_bytes: None,
        fast_scan_available: false,
    }
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn utf16_buffer_to_string(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_target_uses_decimal_byte_contracts() {
        let target = fallback_system_target();

        assert!(target.total_bytes.is_none());
        assert!(target.available_bytes.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_targets_have_root_paths() {
        let targets = scan_targets();

        assert!(
            targets
                .iter()
                .all(|target| target.display_path.ends_with("\\"))
        );
    }
}
