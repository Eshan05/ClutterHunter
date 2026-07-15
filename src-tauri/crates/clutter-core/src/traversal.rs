// Work-stealing traversal design adapted from eDirStat (MIT), Copyright (c) 2026 Cody Neiman.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use crossbeam::{
    channel::Sender,
    deque::{Injector, Steal, Stealer, Worker},
};

use crate::{
    arena::DiscoveredEntry,
    scan::{ScanFailure, ScanWarning},
};

const EVENT_BATCH_SIZE: usize = 512;
const MAX_WORKERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub volume: u64,
    pub file: u64,
    pub links: u32,
}

#[derive(Debug)]
pub enum TraversalEvent {
    Entry {
        entry: DiscoveredEntry,
        identity: Option<FileIdentity>,
    },
    Inaccessible {
        temporary_id: u32,
        path: String,
    },
    Warning(ScanWarning),
}

#[derive(Debug)]
struct ScanTask {
    path: PathBuf,
    temporary_id: u32,
    ancestors: Vec<(u64, u64)>,
    expected_volume: Option<u64>,
    allocation_unit: u64,
}

#[derive(Debug, Default)]
pub struct TraversalReport {
    pub entries_seen: u64,
    pub inaccessible_paths: u64,
    pub lossy_names: u64,
}

pub fn traverse<F>(
    root: &Path,
    cancel: Arc<AtomicBool>,
    mut on_batch: F,
) -> Result<TraversalReport, ScanFailure>
where
    F: FnMut(Vec<TraversalEvent>) -> Result<(), ScanFailure>,
{
    let root_metadata = fs::metadata(root).map_err(|error| {
        ScanFailure::new(
            "TARGET_UNREADABLE",
            format!("Cannot read {}: {error}", root.display()),
            true,
        )
    })?;
    if !root_metadata.is_dir() {
        return Err(ScanFailure::new(
            "TARGET_NOT_DIRECTORY",
            "Traversal targets must be directories or volume roots",
            true,
        ));
    }
    fs::read_dir(root).map_err(|error| {
        ScanFailure::new(
            "TARGET_UNREADABLE",
            format!("Cannot enumerate {}: {error}", root.display()),
            true,
        )
    })?;

    let root_identity = file_identity(root, &root_metadata);
    let expected_volume = root_identity.map(|identity| identity.volume);
    let allocation_unit = allocation_unit(root);
    let mut ancestors = Vec::with_capacity(16);
    if let Some(identity) = root_identity {
        ancestors.push((identity.volume, identity.file));
    }

    let injector = Arc::new(Injector::new());
    injector.push(ScanTask {
        path: root.to_path_buf(),
        temporary_id: 0,
        ancestors,
        expected_volume,
        allocation_unit,
    });

    let worker_count = thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .clamp(1, MAX_WORKERS);
    let mut workers = Vec::with_capacity(worker_count);
    let mut stealers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let worker = Worker::new_fifo();
        stealers.push(worker.stealer());
        workers.push(worker);
    }

    let stealers = Arc::new(stealers);
    let pending_tasks = Arc::new(AtomicUsize::new(1));
    let next_id = Arc::new(AtomicU32::new(1));
    let (event_tx, event_rx) = crossbeam::channel::bounded::<Vec<TraversalEvent>>(64);
    let mut handles = Vec::with_capacity(worker_count);

    for (worker_index, local_worker) in workers.into_iter().enumerate() {
        let injector = Arc::clone(&injector);
        let stealers = Arc::clone(&stealers);
        let pending_tasks = Arc::clone(&pending_tasks);
        let next_id = Arc::clone(&next_id);
        let cancel = Arc::clone(&cancel);
        let event_tx = event_tx.clone();

        handles.push(thread::spawn(move || {
            let mut buffer = Vec::with_capacity(EVENT_BATCH_SIZE);
            loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }

                if let Some(task) =
                    find_task(worker_index, &local_worker, &injector, stealers.as_slice())
                {
                    scan_directory(
                        task,
                        &local_worker,
                        &pending_tasks,
                        &next_id,
                        &cancel,
                        &event_tx,
                        &mut buffer,
                    );
                    pending_tasks.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }

                if pending_tasks.load(Ordering::Acquire) == 0 {
                    break;
                }
                thread::sleep(Duration::from_micros(200));
            }

            flush_events(&event_tx, &mut buffer);
        }));
    }
    drop(event_tx);

    let mut report = TraversalReport::default();
    while let Ok(batch) = event_rx.recv() {
        for event in &batch {
            match event {
                TraversalEvent::Entry { .. } => report.entries_seen += 1,
                TraversalEvent::Inaccessible { .. } => report.inaccessible_paths += 1,
                TraversalEvent::Warning(warning) if warning.code == "LOSSY_NAME" => {
                    report.lossy_names += 1;
                }
                TraversalEvent::Warning(_) => {}
            }
        }
        on_batch(batch)?;
    }

    for handle in handles {
        if handle.join().is_err() {
            return Err(ScanFailure::new(
                "TRAVERSAL_WORKER_FAILED",
                "A traversal worker stopped unexpectedly",
                true,
            ));
        }
    }

    if cancel.load(Ordering::Relaxed) {
        return Err(ScanFailure::new(
            "SCAN_CANCELLED",
            "The scan was cancelled",
            true,
        ));
    }

    Ok(report)
}

fn find_task(
    worker_index: usize,
    local_worker: &Worker<ScanTask>,
    injector: &Injector<ScanTask>,
    stealers: &[Stealer<ScanTask>],
) -> Option<ScanTask> {
    if let Some(task) = local_worker.pop() {
        return Some(task);
    }

    loop {
        match injector.steal() {
            Steal::Success(task) => return Some(task),
            Steal::Retry => continue,
            Steal::Empty => break,
        }
    }

    for (index, stealer) in stealers.iter().enumerate() {
        if index == worker_index {
            continue;
        }
        loop {
            match stealer.steal() {
                Steal::Success(task) => return Some(task),
                Steal::Retry => continue,
                Steal::Empty => break,
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn scan_directory(
    task: ScanTask,
    local_worker: &Worker<ScanTask>,
    pending_tasks: &AtomicUsize,
    next_id: &AtomicU32,
    cancel: &AtomicBool,
    event_tx: &Sender<Vec<TraversalEvent>>,
    buffer: &mut Vec<TraversalEvent>,
) {
    let entries = match fs::read_dir(&task.path) {
        Ok(entries) => entries,
        Err(error) => {
            emit_event(
                event_tx,
                buffer,
                TraversalEvent::Inaccessible {
                    temporary_id: task.temporary_id,
                    path: task.path.to_string_lossy().into_owned(),
                },
            );
            emit_event(
                event_tx,
                buffer,
                TraversalEvent::Warning(ScanWarning {
                    code: "PATH_INACCESSIBLE".to_owned(),
                    detail: format!("{}: {error}", task.path.display()),
                }),
            );
            return;
        }
    };

    for result in entries {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                emit_event(
                    event_tx,
                    buffer,
                    TraversalEvent::Warning(ScanWarning {
                        code: "ENTRY_UNREADABLE".to_owned(),
                        detail: format!("{}: {error}", task.path.display()),
                    }),
                );
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                emit_event(
                    event_tx,
                    buffer,
                    TraversalEvent::Warning(ScanWarning {
                        code: "METADATA_UNREADABLE".to_owned(),
                        detail: format!("{}: {error}", path.display()),
                    }),
                );
                continue;
            }
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                emit_event(
                    event_tx,
                    buffer,
                    TraversalEvent::Warning(ScanWarning {
                        code: "METADATA_UNREADABLE".to_owned(),
                        detail: format!("{}: {error}", path.display()),
                    }),
                );
                continue;
            }
        };

        let identity = file_identity(&path, &metadata);
        let is_reparse_point = file_type.is_symlink() || is_windows_reparse_point(&metadata);
        let is_directory = file_type.is_dir() && !is_reparse_point;
        if is_directory
            && identity.is_some_and(|identity| {
                task.expected_volume
                    .is_some_and(|expected| identity.volume != expected)
            })
        {
            emit_event(
                event_tx,
                buffer,
                TraversalEvent::Warning(ScanWarning {
                    code: "MOUNT_BOUNDARY_SKIPPED".to_owned(),
                    detail: path.to_string_lossy().into_owned(),
                }),
            );
            continue;
        }
        if is_directory
            && identity
                .is_some_and(|identity| task.ancestors.contains(&(identity.volume, identity.file)))
        {
            emit_event(
                event_tx,
                buffer,
                TraversalEvent::Warning(ScanWarning {
                    code: "FILESYSTEM_CYCLE_SKIPPED".to_owned(),
                    detail: path.to_string_lossy().into_owned(),
                }),
            );
            continue;
        }

        let temporary_id = next_id.fetch_add(1, Ordering::Relaxed);
        if temporary_id == u32::MAX {
            cancel.store(true, Ordering::Relaxed);
            emit_event(
                event_tx,
                buffer,
                TraversalEvent::Warning(ScanWarning {
                    code: "SCAN_TOO_LARGE".to_owned(),
                    detail: "The scan exceeded the 32-bit arena index limit".to_owned(),
                }),
            );
            return;
        }

        let os_name = entry.file_name();
        let name = os_name.to_string_lossy();
        if matches!(name, std::borrow::Cow::Owned(_)) {
            emit_event(
                event_tx,
                buffer,
                TraversalEvent::Warning(ScanWarning {
                    code: "LOSSY_NAME".to_owned(),
                    detail: path.to_string_lossy().into_owned(),
                }),
            );
        }
        let logical_bytes = if is_directory || is_reparse_point {
            0
        } else {
            metadata.len()
        };
        let allocated_bytes = if is_directory || is_reparse_point {
            0
        } else {
            allocated_size(&path, &metadata, logical_bytes, task.allocation_unit)
        };
        let modified_at_ms = metadata.modified().ok().and_then(system_time_ms);
        let hard_link_count = identity.map(|identity| identity.links);
        let (is_sparse, is_compressed, is_encrypted) = storage_attributes(&metadata);

        emit_event(
            event_tx,
            buffer,
            TraversalEvent::Entry {
                entry: DiscoveredEntry {
                    temporary_id,
                    parent_temporary_id: Some(task.temporary_id),
                    name: name.into_owned(),
                    is_directory,
                    is_reparse_point,
                    inaccessible: false,
                    is_sparse,
                    is_compressed,
                    is_encrypted,
                    has_named_stream: false,
                    logical_bytes,
                    allocated_bytes,
                    modified_at_ms,
                    hard_link_count,
                    hard_link_alias: false,
                },
                identity,
            },
        );

        if is_directory {
            // Publish the parent before another worker can emit its children.
            flush_events(event_tx, buffer);
            let mut ancestors = task.ancestors.clone();
            if let Some(identity) = identity {
                ancestors.push((identity.volume, identity.file));
            }
            pending_tasks.fetch_add(1, Ordering::Release);
            local_worker.push(ScanTask {
                path,
                temporary_id,
                ancestors,
                expected_volume: task.expected_volume,
                allocation_unit: task.allocation_unit,
            });
        }
    }
}

fn emit_event(
    event_tx: &Sender<Vec<TraversalEvent>>,
    buffer: &mut Vec<TraversalEvent>,
    event: TraversalEvent,
) {
    buffer.push(event);
    if buffer.len() >= EVENT_BATCH_SIZE {
        flush_events(event_tx, buffer);
    }
}

fn flush_events(event_tx: &Sender<Vec<TraversalEvent>>, buffer: &mut Vec<TraversalEvent>) {
    if buffer.is_empty() {
        return;
    }
    let batch = std::mem::replace(buffer, Vec::with_capacity(EVENT_BATCH_SIZE));
    let _ = event_tx.send(batch);
}

fn system_time_ms(value: std::time::SystemTime) -> Option<i64> {
    value
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

#[cfg(unix)]
fn file_identity(_path: &Path, metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    Some(FileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
        links: u32::try_from(metadata.nlink()).unwrap_or(u32::MAX),
    })
}

#[cfg(windows)]
fn file_identity(path: &Path, _metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows::{
        Win32::{
            Foundation::CloseHandle,
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING,
            },
        },
        core::PCWSTR,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .ok()?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result = unsafe { GetFileInformationByHandle(handle, &mut information) };
    let _ = unsafe { CloseHandle(handle) };
    result.ok()?;

    Some(FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        file: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        links: information.nNumberOfLinks,
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_path: &Path, _metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

#[cfg(windows)]
fn storage_attributes(metadata: &fs::Metadata) -> (bool, bool, bool) {
    use std::os::windows::fs::MetadataExt as _;
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_SPARSE_FILE,
    };

    let attributes = metadata.file_attributes();
    (
        attributes & FILE_ATTRIBUTE_SPARSE_FILE.0 != 0,
        attributes & FILE_ATTRIBUTE_COMPRESSED.0 != 0,
        attributes & FILE_ATTRIBUTE_ENCRYPTED.0 != 0,
    )
}

#[cfg(not(windows))]
fn storage_attributes(_metadata: &fs::Metadata) -> (bool, bool, bool) {
    (false, false, false)
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn allocated_size(
    path: &Path,
    metadata: &fs::Metadata,
    logical_bytes: u64,
    allocation_unit: u64,
) -> u64 {
    use std::os::windows::{ffi::OsStrExt as _, fs::MetadataExt as _};
    use windows::{
        Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_SPARSE_FILE, GetCompressedFileSizeW,
        },
        core::PCWSTR,
    };

    if logical_bytes == 0 {
        return 0;
    }
    let attributes = metadata.file_attributes();
    let special = attributes & (FILE_ATTRIBUTE_COMPRESSED.0 | FILE_ATTRIBUTE_SPARSE_FILE.0) != 0;
    if special {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut high = 0u32;
        let low = unsafe { GetCompressedFileSizeW(PCWSTR(wide.as_ptr()), Some(&mut high)) };
        let value = (u64::from(high) << 32) | u64::from(low);
        if value > 0 {
            return value;
        }
    }

    round_to_allocation_unit(logical_bytes, allocation_unit)
}

#[cfg(not(windows))]
fn allocated_size(
    _path: &Path,
    metadata: &fs::Metadata,
    logical_bytes: u64,
    _allocation_unit: u64,
) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        return metadata.blocks().saturating_mul(512);
    }
    #[allow(unreachable_code)]
    logical_bytes
}

#[cfg(windows)]
fn allocation_unit(path: &Path) -> u64 {
    use windows::{Win32::Storage::FileSystem::GetDiskFreeSpaceW, core::PCWSTR};

    let value = path.to_string_lossy();
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' {
        return 4096;
    }
    let root = format!("{}:\\", char::from(bytes[0]).to_ascii_uppercase());
    let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sectors_per_cluster = 0u32;
    let mut bytes_per_sector = 0u32;
    let result = unsafe {
        GetDiskFreeSpaceW(
            PCWSTR(wide.as_ptr()),
            Some(&mut sectors_per_cluster),
            Some(&mut bytes_per_sector),
            None,
            None,
        )
    };
    if result.is_err() {
        return 4096;
    }
    u64::from(sectors_per_cluster)
        .saturating_mul(u64::from(bytes_per_sector))
        .max(1)
}

#[cfg(not(windows))]
fn allocation_unit(_path: &Path) -> u64 {
    512
}

fn round_to_allocation_unit(value: u64, unit: u64) -> u64 {
    value
        .saturating_add(unit.saturating_sub(1))
        .checked_div(unit)
        .unwrap_or(0)
        .saturating_mul(unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_rounding_is_saturating() {
        assert_eq!(round_to_allocation_unit(1, 4096), 4096);
        assert_eq!(round_to_allocation_unit(4096, 4096), 4096);
        assert_eq!(round_to_allocation_unit(4097, 4096), 8192);
    }

    #[test]
    fn traversal_emits_a_small_tree() -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("clutterhunter-traversal-{}", std::process::id()));
        let child = root.join("child");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&child)?;
        fs::write(child.join("one.txt"), b"one")?;
        fs::write(root.join("two.bin"), b"two-two")?;

        let cancel = Arc::new(AtomicBool::new(false));
        let mut entries = 0usize;
        let report = traverse(&root, cancel, |batch| {
            entries += batch
                .iter()
                .filter(|event| matches!(event, TraversalEvent::Entry { .. }))
                .count();
            Ok(())
        })?;

        fs::remove_dir_all(&root)?;
        assert_eq!(entries, 3);
        assert_eq!(report.entries_seen, 3);
        Ok(())
    }
}
