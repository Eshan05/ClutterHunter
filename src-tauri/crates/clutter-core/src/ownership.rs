use std::path::{Path, PathBuf};

use crate::scan::{OwnerMatchKind, OwnerSource, OwnerSummary};

#[derive(Debug, Clone)]
pub struct OwnerRecord {
    pub summary: OwnerSummary,
    pub canonical_root: String,
}

pub fn discover_owners() -> Vec<OwnerRecord> {
    let mut owners = known_owners();
    #[cfg(windows)]
    owners.extend(windows_registry::uninstall_owners());
    owners.sort_by(|left, right| {
        right
            .canonical_root
            .len()
            .cmp(&left.canonical_root.len())
            .then_with(|| {
                owner_source_rank(left.summary.source).cmp(&owner_source_rank(right.summary.source))
            })
            .then_with(|| left.summary.id.cmp(&right.summary.id))
    });
    let mut roots = std::collections::HashSet::new();
    owners.retain(|owner| roots.insert(owner.canonical_root.clone()));
    owners
}

fn owner_source_rank(source: OwnerSource) -> u8 {
    match source {
        OwnerSource::Registry => 0,
        OwnerSource::Appx => 1,
        OwnerSource::KnownRoot => 2,
        OwnerSource::BundledMapping => 3,
    }
}

pub fn match_owner<'a>(path: &str, owners: &'a [OwnerRecord]) -> Option<&'a OwnerRecord> {
    let path = canonical_path(path);
    owners
        .iter()
        .find(|owner| path_has_prefix(&path, &owner.canonical_root))
}

pub fn canonical_path(path: impl AsRef<Path>) -> String {
    let mut value = path
        .as_ref()
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    while value.len() > 3 && value.ends_with('\\') {
        value.pop();
    }
    value
}

fn path_has_prefix(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn known_owners() -> Vec<OwnerRecord> {
    let mut owners = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        push_owner(
            &mut owners,
            "ollama",
            "Ollama",
            OwnerSource::BundledMapping,
            PathBuf::from(&profile).join(".ollama"),
        );
        let scoop = std::env::var_os("SCOOP")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(profile).join("scoop"));
        push_owner(
            &mut owners,
            "scoop",
            "Scoop",
            OwnerSource::BundledMapping,
            scoop,
        );
    }
    if let Some(models) = std::env::var_os("OLLAMA_MODELS") {
        push_owner(
            &mut owners,
            "ollama-models",
            "Ollama models",
            OwnerSource::BundledMapping,
            models,
        );
    }
    if let Some(windows) = std::env::var_os("WINDIR") {
        push_owner(
            &mut owners,
            "windows",
            "Microsoft Windows",
            OwnerSource::KnownRoot,
            windows,
        );
    }
    owners
}

fn push_owner(
    owners: &mut Vec<OwnerRecord>,
    id: &str,
    name: &str,
    source: OwnerSource,
    path: impl AsRef<Path>,
) {
    let canonical_root = canonical_path(path);
    if canonical_root.is_empty() {
        return;
    }
    owners.push(OwnerRecord {
        summary: OwnerSummary {
            id: id.to_owned(),
            name: name.to_owned(),
            source,
            match_kind: OwnerMatchKind::Prefix,
        },
        canonical_root,
    });
}

#[cfg(windows)]
mod windows_registry {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};

    use windows::{
        Management::Deployment::PackageManager,
        Win32::{
            Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
            System::Registry::{
                HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY,
                KEY_WOW64_64KEY, REG_SAM_FLAGS, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey,
                RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
            },
        },
        core::{HSTRING, PCWSTR, PWSTR},
    };

    use super::*;

    const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const APPX_APPLICATIONS_KEY: &str =
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications";

    pub(super) fn uninstall_owners() -> Vec<OwnerRecord> {
        let mut owners = Vec::new();
        for (scope, root) in [("machine", HKEY_LOCAL_MACHINE), ("user", HKEY_CURRENT_USER)] {
            for (view, flag) in [("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] {
                enumerate_view(root, scope, view, KEY_READ | flag, &mut owners);
            }
        }
        let appx = enumerate_appx_winrt();
        if appx.is_empty() {
            enumerate_appx_registry(&mut owners);
        } else {
            owners.extend(appx);
        }
        owners
    }

    fn enumerate_appx_winrt() -> Vec<OwnerRecord> {
        let Some(packages) = PackageManager::new()
            .and_then(|manager| manager.FindPackagesByUserSecurityId(&HSTRING::new()))
            .ok()
        else {
            return Vec::new();
        };
        let mut owners = Vec::new();
        for package in packages {
            let Some(path) = package
                .InstalledPath()
                .ok()
                .map(|path| path.to_string())
                .filter(|path| Path::new(path).is_absolute())
            else {
                continue;
            };
            let canonical_root = canonical_path(path);
            let package_id = package.Id().ok();
            let fallback_name = package_id
                .as_ref()
                .and_then(|id| id.Name().ok())
                .map(|name| name.to_string())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "Windows app package".to_owned());
            let name = package
                .DisplayName()
                .ok()
                .map(|name| name.to_string())
                .filter(|name| !name.is_empty() && !name.starts_with("ms-resource:"))
                .unwrap_or(fallback_name);
            owners.push(OwnerRecord {
                summary: OwnerSummary {
                    id: format!("appx-{:016x}", stable_hash(&canonical_root)),
                    name,
                    source: OwnerSource::Appx,
                    match_kind: OwnerMatchKind::Prefix,
                },
                canonical_root,
            });
        }
        owners
    }

    fn enumerate_appx_registry(owners: &mut Vec<OwnerRecord>) {
        let Some(program_files) = std::env::var_os("ProgramW6432")
            .or_else(|| std::env::var_os("ProgramFiles"))
            .map(PathBuf::from)
        else {
            return;
        };
        let Some(applications) = open_key(HKEY_LOCAL_MACHINE, APPX_APPLICATIONS_KEY, KEY_READ)
        else {
            return;
        };
        for package in enumerate_subkeys(applications.0) {
            if !package.contains('_') {
                continue;
            }
            let name = package
                .split('_')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(&package)
                .to_owned();
            let canonical_root = canonical_path(program_files.join("WindowsApps").join(&package));
            owners.push(OwnerRecord {
                summary: OwnerSummary {
                    id: format!("appx-{:016x}", stable_hash(&canonical_root)),
                    name,
                    source: OwnerSource::Appx,
                    match_kind: OwnerMatchKind::Prefix,
                },
                canonical_root,
            });
        }
    }

    fn enumerate_view(
        root: HKEY,
        scope: &str,
        view: &str,
        access: REG_SAM_FLAGS,
        owners: &mut Vec<OwnerRecord>,
    ) {
        let Some(uninstall) = open_key(root, UNINSTALL_KEY, access) else {
            return;
        };
        for subkey in enumerate_subkeys(uninstall.0) {
            let Some(application) = open_key(uninstall.0, &subkey, KEY_READ) else {
                continue;
            };
            let Some(name) = read_string(application.0, "DisplayName") else {
                continue;
            };
            let Some(location) = read_string(application.0, "InstallLocation") else {
                continue;
            };
            if location.trim().is_empty() || !Path::new(&location).is_absolute() {
                continue;
            }
            let canonical_root = canonical_path(&location);
            owners.push(OwnerRecord {
                summary: OwnerSummary {
                    id: format!(
                        "registry-{scope}-{view}-{:016x}",
                        stable_hash(&canonical_root)
                    ),
                    name,
                    source: OwnerSource::Registry,
                    match_kind: OwnerMatchKind::Prefix,
                },
                canonical_root,
            });
        }
    }

    fn open_key(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> Option<RegistryKey> {
        let path = wide(path);
        let mut key = HKEY::default();
        let status = unsafe { RegOpenKeyExW(root, PCWSTR(path.as_ptr()), None, access, &mut key) };
        (status == ERROR_SUCCESS).then_some(RegistryKey(key))
    }

    fn enumerate_subkeys(key: HKEY) -> Vec<String> {
        let mut names = Vec::new();
        for index in 0..u32::MAX {
            let mut buffer = vec![0u16; 512];
            let mut length = buffer.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    Some(PWSTR(buffer.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_MORE_DATA || status != ERROR_SUCCESS {
                continue;
            }
            names.push(
                OsString::from_wide(&buffer[..length as usize])
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        names
    }

    fn read_string(key: HKEY, name: &str) -> Option<String> {
        let name = wide(name);
        let mut bytes = 0u32;
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                flags,
                None,
                None,
                Some(&mut bytes),
            )
        };
        if status != ERROR_SUCCESS || !(2..=128 * 1024).contains(&bytes) {
            return None;
        }
        let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name.as_ptr()),
                flags,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut bytes),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let length = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        let value = OsString::from_wide(&buffer[..length])
            .to_string_lossy()
            .trim()
            .to_owned();
        (!value.is_empty()).then_some(value)
    }

    fn stable_hash(value: &str) -> u64 {
        value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
        })
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_owner_wins_at_path_boundaries() {
        let owners = vec![
            OwnerRecord {
                summary: OwnerSummary {
                    id: "specific".to_owned(),
                    name: "Specific".to_owned(),
                    source: OwnerSource::Registry,
                    match_kind: OwnerMatchKind::Prefix,
                },
                canonical_root: canonical_path(r"C:\Apps\Specific"),
            },
            OwnerRecord {
                summary: OwnerSummary {
                    id: "apps".to_owned(),
                    name: "Apps".to_owned(),
                    source: OwnerSource::KnownRoot,
                    match_kind: OwnerMatchKind::Prefix,
                },
                canonical_root: canonical_path(r"C:\Apps"),
            },
        ];

        assert_eq!(
            match_owner(r"C:\Apps\Specific\cache", &owners).map(|owner| owner.summary.id.as_str()),
            Some("specific")
        );
        assert!(match_owner(r"C:\Application", &owners).is_none());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "reads installed Win32 and AppX ownership from the current Windows machine"]
    fn windows_owner_discovery_smoke_test() {
        let owners = discover_owners();
        let registry = owners
            .iter()
            .filter(|owner| owner.summary.source == OwnerSource::Registry)
            .count();
        let appx = owners
            .iter()
            .filter(|owner| owner.summary.source == OwnerSource::Appx)
            .count();
        println!(
            "owners={} registry={} appx={} known_or_bundled={}",
            owners.len(),
            registry,
            appx,
            owners.len().saturating_sub(registry + appx)
        );

        assert!(owners.iter().any(|owner| owner.summary.id == "windows"));
        assert!(owners.iter().all(|owner| {
            Path::new(&owner.canonical_root).is_absolute()
                && !owner.canonical_root.ends_with('\\')
                && !owner.summary.name.trim().is_empty()
        }));
        let mut roots = std::collections::HashSet::new();
        assert!(
            owners
                .iter()
                .all(|owner| roots.insert(&owner.canonical_root))
        );
        assert!(
            owners
                .iter()
                .filter(|owner| owner.summary.source == OwnerSource::Appx)
                .all(|owner| !owner.summary.name.starts_with("ms-resource:"))
        );
    }
}
