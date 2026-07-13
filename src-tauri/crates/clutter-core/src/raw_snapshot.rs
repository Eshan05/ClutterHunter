use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::windows::{ffi::OsStrExt as _, io::FromRawHandle as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[cfg(test)]
use std::collections::{HashMap, HashSet};

#[cfg(test)]
use clutter_protocol::RawScanEntry;
use clutter_protocol::{
    HelperMessage, PROTOCOL_VERSION, RAW_FRAME_LIMIT, RAW_NAME_BATCH_SIZE, RAW_NODE_BATCH_SIZE,
    RawArenaSnapshot, RawScanPhase, RawScanStatistics,
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_CANCELLED, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE,
            HLOCAL, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::PIPE_ACCESS_DUPLEX,
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_NOWAIT,
                PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
                SetNamedPipeHandleState,
            },
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{
                GetCurrentProcess, GetExitCodeProcess, GetProcessId, OpenProcessToken,
                WaitForSingleObject,
            },
        },
        UI::Shell::{
            SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
        },
    },
    core::{HRESULT, PCWSTR, PWSTR},
};

#[cfg(test)]
use crate::arena::{ArenaBuilder, DiscoveredEntry};
use crate::{
    arena::ScanArena,
    scan::{ScanFailure, ScanWarning},
};

#[cfg(test)]
const ROOT_RECORD: u64 = 5;
const MAX_RAW_STREAM_NODES: usize = 12_000_000;
const MAX_RAW_STREAM_NAME_BYTES: usize = 512 * 1024 * 1024;

pub struct RawSnapshotProduct {
    pub arena: ScanArena,
    pub statistics: RawScanStatistics,
    pub warnings: Vec<ScanWarning>,
}

pub fn scan_with_helper(
    target: &str,
    root_path: PathBuf,
    session_id: String,
    cancel: Arc<AtomicBool>,
    on_progress: &mut dyn FnMut(RawScanPhase, u64, u64, u64),
) -> Result<RawSnapshotProduct, ScanFailure> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| {
        ScanFailure::new(
            "RANDOM_SOURCE_FAILED",
            format!("Could not create a scanner helper nonce: {error}"),
            true,
        )
    })?;
    let nonce_hex = encode_nonce(&nonce);
    let pipe_name = format!(r"\\.\pipe\ClutterHunter-{nonce_hex}");
    let pipe = PipeServer::create(&pipe_name)?;
    let helper = helper_path()?;
    let parameters = [
        OsString::from("stream"),
        OsString::from(target),
        OsString::from(&pipe_name),
        OsString::from(&nonce_hex),
    ];
    let process = launch_elevated(&helper, &parameters)?;
    let expected_pid = unsafe { GetProcessId(process.0) };
    if expected_pid == 0 {
        return Err(ScanFailure::new(
            "RAW_NTFS_HELPER_FAILED",
            "Windows did not return the scanner helper process ID",
            true,
        ));
    }
    let mut pipe = pipe.connect(process.0, expected_pid)?;
    let stream_result = read_stream(
        &mut pipe,
        target,
        &nonce,
        expected_pid,
        &cancel,
        on_progress,
    );
    drop(pipe);
    wait_for_helper(process.0)?;

    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process.0, &mut exit_code) }.map_err(|error| {
        ScanFailure::new(
            "RAW_NTFS_HELPER_FAILED",
            format!("Could not read scanner helper status: {error}"),
            true,
        )
    })?;
    let stream = stream_result?;
    if exit_code != 0 {
        return Err(ScanFailure::new(
            "RAW_NTFS_HELPER_FAILED",
            format!("The elevated scanner helper exited with status {exit_code}"),
            true,
        ));
    }

    let RawStreamProduct {
        arena: raw_arena,
        mut statistics,
        mut warnings,
    } = stream;
    let adopt_started = std::time::Instant::now();
    let arena = ScanArena::from_raw_snapshot(root_path, session_id, raw_arena)?;
    statistics.adopt_ms = u64::try_from(adopt_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    statistics.host_peak_working_set_bytes = process_peak_working_set_bytes().unwrap_or(0);
    if arena.entry_count() as u64 != statistics.entry_count {
        warnings.push(ScanWarning {
            code: "RAW_ENTRY_COUNT_MISMATCH".to_owned(),
            detail: format!(
                "The helper reported {} entries but {} were indexed",
                statistics.entry_count,
                arena.entry_count()
            ),
        });
    }
    Ok(RawSnapshotProduct {
        arena,
        statistics,
        warnings,
    })
}

fn process_peak_working_set_bytes() -> Option<u64> {
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..PROCESS_MEMORY_COUNTERS::default()
    };
    unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    }
    .ok()?;
    u64::try_from(counters.PeakWorkingSetSize).ok()
}

#[cfg(test)]
fn assemble(
    entries: Vec<RawScanEntry>,
    root_path: PathBuf,
    session_id: String,
) -> Result<(ScanArena, Vec<ScanWarning>), ScanFailure> {
    let mut children = HashMap::<u64, Vec<usize>>::new();
    let mut directory_records = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        children
            .entry(entry.parent_record_id)
            .or_default()
            .push(index);
        if entry.is_directory {
            directory_records.insert(entry.record_id);
        }
    }
    for indices in children.values_mut() {
        indices.sort_unstable_by(|left, right| {
            entries[*left]
                .record_id
                .cmp(&entries[*right].record_id)
                .then_with(|| entries[*left].link_index.cmp(&entries[*right].link_index))
        });
    }

    let mut builder = ArenaBuilder::new(root_path)?;
    let mut emitted = vec![false; entries.len()];
    let mut expanded_directories = HashSet::new();
    let mut next_temporary_id = 1u32;
    let mut orphaned = 0u64;
    emit_children(
        ROOT_RECORD,
        0,
        &entries,
        &children,
        &mut emitted,
        &mut expanded_directories,
        &mut next_temporary_id,
        &mut builder,
    )?;

    let orphan_roots: Vec<_> = entries
        .iter()
        .enumerate()
        .filter(|(index, entry)| {
            !emitted[*index]
                && (!directory_records.contains(&entry.parent_record_id)
                    || entry.parent_record_id == entry.record_id)
        })
        .map(|(index, _)| index)
        .collect();
    for index in orphan_roots {
        orphaned = orphaned.saturating_add(emit_orphan_subtree(
            index,
            &entries,
            &children,
            &mut emitted,
            &mut expanded_directories,
            &mut next_temporary_id,
            &mut builder,
        )?);
    }
    while let Some(index) = emitted.iter().position(|value| !*value) {
        orphaned = orphaned.saturating_add(emit_orphan_subtree(
            index,
            &entries,
            &children,
            &mut emitted,
            &mut expanded_directories,
            &mut next_temporary_id,
            &mut builder,
        )?);
    }

    let warnings = (orphaned > 0)
        .then(|| ScanWarning {
            code: "ORPHAN_MFT_PARENT".to_owned(),
            detail: format!(
                "{orphaned} MFT entries had no reachable parent and were attached to the scan root"
            ),
        })
        .into_iter()
        .collect();
    Ok((builder.finish(session_id), warnings))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn emit_children(
    parent_record: u64,
    parent_temporary_id: u32,
    entries: &[RawScanEntry],
    children: &HashMap<u64, Vec<usize>>,
    emitted: &mut [bool],
    expanded_directories: &mut HashSet<u64>,
    next_temporary_id: &mut u32,
    builder: &mut ArenaBuilder,
) -> Result<(), ScanFailure> {
    let mut stack = vec![(parent_record, parent_temporary_id)];
    while let Some((record, temporary_parent)) = stack.pop() {
        if !expanded_directories.insert(record) {
            continue;
        }
        let Some(indices) = children.get(&record) else {
            continue;
        };
        for index in indices.iter().rev().copied() {
            if emitted[index] {
                continue;
            }
            let entry = &entries[index];
            let temporary_id = *next_temporary_id;
            *next_temporary_id = next_temporary_id.checked_add(1).ok_or_else(|| {
                ScanFailure::new(
                    "SCAN_TOO_LARGE",
                    "The raw scan exceeded the arena index limit",
                    false,
                )
            })?;
            builder.push(discovered_entry(entry, temporary_id, temporary_parent))?;
            emitted[index] = true;
            if entry.is_directory {
                stack.push((entry.record_id, temporary_id));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn emit_orphan_subtree(
    index: usize,
    entries: &[RawScanEntry],
    children: &HashMap<u64, Vec<usize>>,
    emitted: &mut [bool],
    expanded_directories: &mut HashSet<u64>,
    next_temporary_id: &mut u32,
    builder: &mut ArenaBuilder,
) -> Result<u64, ScanFailure> {
    if emitted[index] {
        return Ok(0);
    }
    let entry = &entries[index];
    let temporary_id = *next_temporary_id;
    *next_temporary_id = next_temporary_id.checked_add(1).ok_or_else(|| {
        ScanFailure::new(
            "SCAN_TOO_LARGE",
            "The raw scan exceeded the arena index limit",
            false,
        )
    })?;
    builder.push(discovered_entry(entry, temporary_id, 0))?;
    emitted[index] = true;
    if entry.is_directory {
        emit_children(
            entry.record_id,
            temporary_id,
            entries,
            children,
            emitted,
            expanded_directories,
            next_temporary_id,
            builder,
        )?;
    }
    Ok(1)
}

#[cfg(test)]
fn discovered_entry(entry: &RawScanEntry, temporary_id: u32, parent: u32) -> DiscoveredEntry {
    DiscoveredEntry {
        temporary_id,
        parent_temporary_id: Some(parent),
        name: entry.name.clone(),
        is_directory: entry.is_directory,
        is_reparse_point: entry.is_reparse_point,
        inaccessible: false,
        logical_bytes: entry.logical_bytes,
        allocated_bytes: entry.allocated_bytes,
        modified_at_ms: entry.modified_at_ms,
        hard_link_count: (entry.hard_link_count > 0).then_some(entry.hard_link_count),
        hard_link_alias: entry.hard_link_alias,
    }
}

struct RawStreamProduct {
    arena: RawArenaSnapshot,
    statistics: RawScanStatistics,
    warnings: Vec<ScanWarning>,
}

fn read_stream(
    reader: &mut (impl Read + Write),
    target: &str,
    nonce: &[u8; 32],
    expected_pid: u32,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(RawScanPhase, u64, u64, u64),
) -> Result<RawStreamProduct, ScanFailure> {
    let hello = match read_frame(reader)? {
        HelperMessage::Hello(hello) => hello,
        _ => {
            return Err(invalid_stream(
                "The scanner stream did not begin with a hello frame",
            ));
        }
    };
    if hello.protocol_version != PROTOCOL_VERSION
        || hello.nonce != *nonce
        || hello.helper_pid != expected_pid
        || !hello.target.eq_ignore_ascii_case(target)
    {
        return Err(invalid_stream(
            "The scanner helper identity or protocol did not match this scan",
        ));
    }

    let mut expected_counts = None;
    let mut nodes = Vec::new();
    let mut names = Vec::new();
    let mut warnings = Vec::new();
    let mut node_sequence = 0u32;
    let mut name_sequence = 0u32;
    let mut cancellation_sent = false;
    loop {
        if cancel.load(Ordering::Acquire) && !cancellation_sent {
            write_frame(reader, &HelperMessage::Cancel)?;
            cancellation_sent = true;
        }
        match read_frame(reader)? {
            HelperMessage::Progress {
                phase,
                records_seen,
                mft_bytes_read,
                elapsed_ms,
            } => on_progress(phase, records_seen, mft_bytes_read, elapsed_ms),
            HelperMessage::Warning { code, detail } => {
                if warnings.len() >= 1024 || code.len() > 128 || detail.len() > 64 * 1024 {
                    return Err(invalid_stream("A scanner stream warning was invalid"));
                }
                warnings.push(ScanWarning { code, detail });
            }
            HelperMessage::ArenaHeader {
                node_count,
                name_bytes,
            } => {
                if expected_counts.is_some()
                    || node_count == 0
                    || node_count as usize > MAX_RAW_STREAM_NODES
                    || name_bytes as usize > MAX_RAW_STREAM_NAME_BYTES
                {
                    return Err(invalid_stream("The scanner arena header was invalid"));
                }
                let node_count = node_count as usize;
                let name_bytes = name_bytes as usize;
                nodes.try_reserve_exact(node_count).map_err(|error| {
                    ScanFailure::new(
                        "SCAN_MEMORY_LIMIT",
                        format!("Could not reserve the scanner node arena: {error}"),
                        true,
                    )
                })?;
                names.try_reserve_exact(name_bytes).map_err(|error| {
                    ScanFailure::new(
                        "SCAN_MEMORY_LIMIT",
                        format!("Could not reserve the scanner name arena: {error}"),
                        true,
                    )
                })?;
                expected_counts = Some((node_count, name_bytes));
            }
            HelperMessage::NodeBatch {
                sequence,
                nodes: batch,
            } => {
                let Some((expected_nodes, _)) = expected_counts else {
                    return Err(invalid_stream(
                        "A scanner node batch arrived before its header",
                    ));
                };
                if sequence != node_sequence
                    || batch.is_empty()
                    || batch.len() > RAW_NODE_BATCH_SIZE
                    || !names.is_empty()
                    || nodes.len().saturating_add(batch.len()) > expected_nodes
                {
                    return Err(invalid_stream("A scanner node batch was invalid"));
                }
                node_sequence = node_sequence.saturating_add(1);
                nodes.extend(batch);
            }
            HelperMessage::NameBatch { sequence, bytes } => {
                let Some((expected_nodes, expected_names)) = expected_counts else {
                    return Err(invalid_stream(
                        "A scanner name batch arrived before its header",
                    ));
                };
                if sequence != name_sequence
                    || bytes.is_empty()
                    || bytes.len() > RAW_NAME_BATCH_SIZE
                    || nodes.len() != expected_nodes
                    || names.len().saturating_add(bytes.len()) > expected_names
                {
                    return Err(invalid_stream("A scanner name batch was invalid"));
                }
                name_sequence = name_sequence.saturating_add(1);
                names.extend(bytes);
            }
            HelperMessage::Complete { statistics } => {
                let Some((expected_nodes, expected_names)) = expected_counts else {
                    return Err(invalid_stream(
                        "The scanner stream completed without an arena",
                    ));
                };
                if nodes.len() != expected_nodes || names.len() != expected_names {
                    return Err(invalid_stream("The scanner stream arena was incomplete"));
                }
                let arena = RawArenaSnapshot { nodes, names };
                arena.validate().map_err(invalid_stream)?;
                return Ok(RawStreamProduct {
                    arena,
                    statistics,
                    warnings,
                });
            }
            HelperMessage::Error {
                code,
                recoverable,
                detail,
            } => return Err(ScanFailure::new(code, detail, recoverable)),
            HelperMessage::Hello(_) | HelperMessage::Cancel => {
                return Err(invalid_stream("The scanner stream frame order was invalid"));
            }
        }
    }
}

fn read_frame(reader: &mut impl Read) -> Result<HelperMessage, ScanFailure> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).map_err(|error| {
        ScanFailure::new(
            "RAW_NTFS_HELPER_FAILED",
            format!("The scanner stream ended unexpectedly: {error}"),
            true,
        )
    })?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > RAW_FRAME_LIMIT {
        return Err(invalid_stream(
            "A scanner stream frame exceeded its bounded size",
        ));
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes).map_err(|error| {
        ScanFailure::new(
            "RAW_NTFS_HELPER_FAILED",
            format!("The scanner stream frame was truncated: {error}"),
            true,
        )
    })?;
    let (message, consumed): (HelperMessage, usize) = bincode::serde::decode_from_slice(
        &bytes,
        bincode::config::standard().with_limit::<RAW_FRAME_LIMIT>(),
    )
    .map_err(|error| {
        invalid_stream(format!(
            "A scanner stream frame could not be decoded: {error}"
        ))
    })?;
    if consumed != bytes.len() {
        return Err(invalid_stream("A scanner stream frame had trailing data"));
    }
    Ok(message)
}

fn write_frame(writer: &mut impl Write, message: &HelperMessage) -> Result<(), ScanFailure> {
    let bytes =
        bincode::serde::encode_to_vec(message, bincode::config::standard()).map_err(|error| {
            invalid_stream(format!(
                "A scanner control frame could not be encoded: {error}"
            ))
        })?;
    if bytes.is_empty() || bytes.len() > RAW_FRAME_LIMIT {
        return Err(invalid_stream(
            "A scanner control frame exceeded its bounded size",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| invalid_stream("A scanner control frame length overflowed"))?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .and_then(|_| writer.flush())
        .map_err(|error| {
            ScanFailure::new(
                "RAW_NTFS_HELPER_FAILED",
                format!("Could not signal the scanner helper: {error}"),
                true,
            )
        })
}

fn invalid_stream(detail: impl Into<String>) -> ScanFailure {
    ScanFailure::new("RAW_STREAM_INVALID", detail, false)
}

struct PipeServer {
    handle: Option<HANDLE>,
}

impl PipeServer {
    fn create(name: &str) -> Result<Self, ScanFailure> {
        let descriptor = current_user_security_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: false.into(),
        };
        let name = wide(name);
        let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                mode,
                1,
                1024 * 1024,
                1024 * 1024,
                0,
                Some(&attributes),
            )
        };
        if handle.is_invalid() {
            return Err(ScanFailure::new(
                "RAW_STREAM_UNAVAILABLE",
                format!(
                    "Could not create the local scanner stream: {}",
                    windows::core::Error::from_thread()
                ),
                true,
            ));
        }
        Ok(Self {
            handle: Some(handle),
        })
    }

    fn connect(mut self, process: HANDLE, expected_pid: u32) -> Result<File, ScanFailure> {
        let handle = self
            .handle
            .expect("pipe handle must exist before connection");
        loop {
            match unsafe { ConnectNamedPipe(handle, None) } {
                Ok(()) => break,
                Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => break,
                Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_LISTENING.0) => {}
                Err(error) => {
                    return Err(ScanFailure::new(
                        "RAW_STREAM_UNAVAILABLE",
                        format!("The scanner helper could not connect to its stream: {error}"),
                        true,
                    ));
                }
            }
            match unsafe { WaitForSingleObject(process, 0) } {
                WAIT_OBJECT_0 => {
                    return Err(ScanFailure::new(
                        "RAW_NTFS_HELPER_FAILED",
                        "The scanner helper exited before connecting to its stream",
                        true,
                    ));
                }
                WAIT_FAILED => {
                    return Err(ScanFailure::new(
                        "RAW_NTFS_HELPER_FAILED",
                        "Waiting for the scanner helper connection failed",
                        true,
                    ));
                }
                _ => thread::sleep(Duration::from_millis(25)),
            }
        }
        let blocking_mode = PIPE_READMODE_BYTE | PIPE_WAIT;
        unsafe { SetNamedPipeHandleState(handle, Some(&blocking_mode), None, None) }.map_err(
            |error| {
                ScanFailure::new(
                    "RAW_STREAM_UNAVAILABLE",
                    format!("Could not activate the scanner stream: {error}"),
                    true,
                )
            },
        )?;
        let mut client_pid = 0u32;
        unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) }.map_err(|error| {
            ScanFailure::new(
                "RAW_STREAM_INVALID",
                format!("Could not verify the scanner stream process: {error}"),
                false,
            )
        })?;
        if client_pid != expected_pid {
            return Err(invalid_stream(
                "The scanner stream client was not the launched helper process",
            ));
        }
        self.handle = None;
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = unsafe { CloseHandle(handle) };
        }
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn current_user_security_descriptor() -> Result<LocalSecurityDescriptor, ScanFailure> {
    let sid = current_user_sid()?;
    let sddl = wide(format!("D:P(A;;GA;;;{sid})"));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|error| {
        ScanFailure::new(
            "RAW_STREAM_UNAVAILABLE",
            format!("Could not secure the scanner stream: {error}"),
            true,
        )
    })?;
    Ok(LocalSecurityDescriptor(descriptor))
}

fn current_user_sid() -> Result<String, ScanFailure> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|error| {
        ScanFailure::new(
            "RAW_STREAM_UNAVAILABLE",
            format!("Could not inspect the current Windows identity: {error}"),
            true,
        )
    })?;
    let token = TokenHandle(token);
    let mut length = 0u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut length) };
    if length == 0 {
        return Err(ScanFailure::new(
            "RAW_STREAM_UNAVAILABLE",
            "Windows did not report the current user identity size",
            true,
        ));
    }
    let word_count = (length as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; word_count];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &mut length,
        )
    }
    .map_err(|error| {
        ScanFailure::new(
            "RAW_STREAM_UNAVAILABLE",
            format!("Could not read the current Windows identity: {error}"),
            true,
        )
    })?;
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = PWSTR::default();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) }.map_err(|error| {
        ScanFailure::new(
            "RAW_STREAM_UNAVAILABLE",
            format!("Could not encode the current Windows identity: {error}"),
            true,
        )
    })?;
    let sid = unsafe { sid_text.to_string() };
    let _ = unsafe { LocalFree(Some(HLOCAL(sid_text.0.cast()))) };
    sid.map_err(|error| {
        ScanFailure::new(
            "RAW_STREAM_UNAVAILABLE",
            format!("Could not decode the current Windows identity: {error}"),
            true,
        )
    })
}

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn helper_path() -> Result<PathBuf, ScanFailure> {
    let executable = std::env::current_exe().map_err(|error| {
        ScanFailure::new(
            "RAW_NTFS_HELPER_MISSING",
            format!("Could not locate the application executable: {error}"),
            true,
        )
    })?;
    let directory = executable.parent().ok_or_else(|| {
        ScanFailure::new(
            "RAW_NTFS_HELPER_MISSING",
            "The scanner helper directory could not be resolved",
            true,
        )
    })?;
    let mut directories = vec![directory];
    if directory.file_name() == Some(OsStr::new("deps"))
        && let Some(target_directory) = directory.parent()
    {
        directories.push(target_directory);
    }
    directories
        .into_iter()
        .flat_map(|directory| {
            [
                directory.join("clutter-scanner-helper.exe"),
                directory.join("clutter-scanner-helper-x86_64-pc-windows-msvc.exe"),
                directory.join("clutter-scanner-helper-aarch64-pc-windows-msvc.exe"),
            ]
        })
        .find(|path| path.is_file())
        .ok_or_else(|| {
            ScanFailure::new(
                "RAW_NTFS_HELPER_MISSING",
                "The raw scanner helper is not installed beside ClutterHunter",
                true,
            )
        })
}

fn launch_elevated(
    executable: &Path,
    arguments: &[OsString],
) -> Result<ProcessHandle, ScanFailure> {
    let verb = wide("runas");
    let file = wide(executable.as_os_str());
    let parameters = wide(join_arguments(arguments));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: 0,
        ..SHELLEXECUTEINFOW::default()
    };
    unsafe { ShellExecuteExW(&mut info) }.map_err(|error| {
        ScanFailure::new(
            elevation_failure_code(error.code()),
            format!("The elevated scanner helper could not be started: {error}"),
            true,
        )
    })?;
    if info.hProcess.is_invalid() {
        return Err(ScanFailure::new(
            "RAW_NTFS_ELEVATION_FAILED",
            "Windows did not return a scanner helper process handle",
            true,
        ));
    }
    Ok(ProcessHandle(info.hProcess))
}

fn elevation_failure_code(code: HRESULT) -> &'static str {
    if code == HRESULT::from_win32(ERROR_CANCELLED.0) {
        "ELEVATION_DECLINED"
    } else {
        "RAW_NTFS_ELEVATION_FAILED"
    }
}

fn wait_for_helper(process: HANDLE) -> Result<(), ScanFailure> {
    loop {
        let status = unsafe { WaitForSingleObject(process, 100) };
        if status == WAIT_OBJECT_0 {
            return Ok(());
        }
        if status == WAIT_FAILED {
            return Err(ScanFailure::new(
                "RAW_NTFS_HELPER_FAILED",
                "Waiting for the elevated scanner helper failed",
                true,
            ));
        }
        if status != WAIT_TIMEOUT {
            return Err(ScanFailure::new(
                "RAW_NTFS_HELPER_FAILED",
                "The elevated scanner helper returned an unexpected wait status",
                true,
            ));
        }
    }
}

fn join_arguments(arguments: &[OsString]) -> OsString {
    let mut result = OsString::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            result.push(" ");
        }
        result.push(quote_argument(argument));
    }
    result
}

fn quote_argument(argument: &OsStr) -> OsString {
    let text = argument.to_string_lossy();
    if !text.is_empty()
        && !text
            .chars()
            .any(|value| value.is_whitespace() || value == '"')
    {
        return argument.to_owned();
    }
    let mut result = String::from("\"");
    let mut backslashes = 0usize;
    for character in text.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            result.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
            result.push('"');
        } else {
            result.push_str(&"\\".repeat(backslashes));
            result.push(character);
        }
        backslashes = 0;
    }
    result.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    result.push('"');
    OsString::from(result)
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn encode_nonce(nonce: &[u8; 32]) -> String {
    let mut result = String::with_capacity(64);
    for byte in nonce {
        use std::fmt::Write as _;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::{ScanBackendEngine, TraversalBackend},
        scan::{
            ItemQuery, ItemSort, ScanBackend, ScanRequest, ScanTarget, ScanTargetKind,
            SortDirection,
        },
    };
    use clutter_protocol::{HelperHello, RAW_NODE_FLAG_DIRECTORY, RAW_NODE_NO_INDEX, RawArenaNode};

    #[test]
    fn assembler_restores_record_hierarchy_and_alias_allocation() -> Result<(), ScanFailure> {
        let entries = vec![
            raw_entry(30, ROOT_RECORD, 0, "folder", true, 0),
            raw_entry(31, 30, 0, "file.bin", false, 4096),
            RawScanEntry {
                hard_link_alias: true,
                allocated_bytes: 0,
                link_index: 1,
                parent_record_id: ROOT_RECORD,
                name: "alias.bin".to_owned(),
                ..raw_entry(31, 30, 0, "file.bin", false, 4096)
            },
        ];
        let (arena, warnings) = assemble(entries, PathBuf::from("C:\\"), "scan-raw".to_owned())?;
        assert!(warnings.is_empty());
        assert_eq!(arena.allocated_bytes(), 4096);
        let root = arena.query(&ItemQuery {
            parent_id: None,
            sort: ItemSort::Name,
            direction: SortDirection::Asc,
            cursor: None,
            limit: 100,
            ..ItemQuery::default()
        })?;
        assert_eq!(root.items.len(), 2);
        Ok(())
    }

    #[test]
    fn command_line_quoting_preserves_trailing_backslashes() {
        assert_eq!(quote_argument(OsStr::new("C:\\")), OsString::from("C:\\"));
        assert_eq!(
            quote_argument(OsStr::new("C:\\Path With Space\\")),
            OsString::from("\"C:\\Path With Space\\\\\"")
        );
    }

    #[test]
    fn cancelled_uac_prompt_has_a_stable_failure_code() {
        assert_eq!(
            elevation_failure_code(HRESULT::from_win32(ERROR_CANCELLED.0)),
            "ELEVATION_DECLINED"
        );
        assert_eq!(
            elevation_failure_code(HRESULT::from_win32(5)),
            "RAW_NTFS_ELEVATION_FAILED"
        );
    }

    #[test]
    fn framed_stream_reassembles_and_validates_the_arena() -> Result<(), ScanFailure> {
        let nonce = [9; 32];
        let messages = vec![
            HelperMessage::Hello(HelperHello {
                protocol_version: PROTOCOL_VERSION,
                nonce,
                helper_pid: 42,
                target: "C:\\".to_owned(),
            }),
            HelperMessage::Progress {
                phase: RawScanPhase::Enumerating,
                records_seen: 1,
                mft_bytes_read: 1024,
                elapsed_ms: 12,
            },
            HelperMessage::ArenaHeader {
                node_count: 1,
                name_bytes: 3,
            },
            HelperMessage::NodeBatch {
                sequence: 0,
                nodes: vec![stream_root()],
            },
            HelperMessage::NameBatch {
                sequence: 0,
                bytes: b"C:\\".to_vec(),
            },
            HelperMessage::Complete {
                statistics: RawScanStatistics::default(),
            },
        ];
        let mut reader = std::io::Cursor::new(encode_frames(&messages));
        let mut progress = Vec::new();
        let cancel = AtomicBool::new(false);
        let product = read_stream(
            &mut reader,
            "C:\\",
            &nonce,
            42,
            &cancel,
            &mut |phase, records, _, _| {
                progress.push((phase, records));
            },
        )?;

        assert_eq!(product.arena.nodes.len(), 1);
        assert_eq!(product.arena.names, b"C:\\");
        assert_eq!(progress, vec![(RawScanPhase::Enumerating, 1)]);
        Ok(())
    }

    #[test]
    fn framed_stream_rejects_out_of_order_batches() {
        let nonce = [3; 32];
        let messages = vec![
            HelperMessage::Hello(HelperHello {
                protocol_version: PROTOCOL_VERSION,
                nonce,
                helper_pid: 7,
                target: "C:\\".to_owned(),
            }),
            HelperMessage::ArenaHeader {
                node_count: 1,
                name_bytes: 3,
            },
            HelperMessage::NodeBatch {
                sequence: 1,
                nodes: vec![stream_root()],
            },
        ];
        let cancel = AtomicBool::new(false);
        let error = read_stream(
            &mut std::io::Cursor::new(encode_frames(&messages)),
            "C:\\",
            &nonce,
            7,
            &cancel,
            &mut |_, _, _, _| {},
        )
        .err()
        .expect("the invalid stream must fail");

        assert_eq!(error.code, "RAW_STREAM_INVALID");
    }

    #[test]
    fn helper_error_frame_is_preserved_without_partial_results() {
        let nonce = [4; 32];
        let messages = vec![
            HelperMessage::Hello(HelperHello {
                protocol_version: PROTOCOL_VERSION,
                nonce,
                helper_pid: 8,
                target: "C:\\".to_owned(),
            }),
            HelperMessage::Error {
                code: "RAW_NTFS_SCAN_FAILED".to_owned(),
                recoverable: true,
                detail: "fixture helper crash".to_owned(),
            },
        ];
        let error = read_stream(
            &mut std::io::Cursor::new(encode_frames(&messages)),
            "C:\\",
            &nonce,
            8,
            &AtomicBool::new(false),
            &mut |_, _, _, _| {},
        )
        .err()
        .expect("a helper error frame must fail the scan");

        assert_eq!(error.code, "RAW_NTFS_SCAN_FAILED");
        assert!(error.recoverable);
    }

    #[test]
    fn duplex_pipe_delivers_cancel_to_the_client() -> Result<(), ScanFailure> {
        let nonce = encode_nonce(&[6; 32]);
        let pipe_name = format!(r"\\.\pipe\ClutterHunter-test-{nonce}");
        let server = PipeServer::create(&pipe_name)?;
        let client_name = pipe_name.clone();
        let client = thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(client_name)
                .unwrap();
            read_frame(&mut file).unwrap()
        });
        let process = unsafe { GetCurrentProcess() };
        let mut server = server.connect(process, std::process::id())?;
        write_frame(&mut server, &HelperMessage::Cancel)?;

        assert!(matches!(client.join().unwrap(), HelperMessage::Cancel));
        Ok(())
    }

    #[test]
    #[ignore = "requires Windows elevation and a real NTFS volume"]
    fn elevated_named_pipe_scan_smoke_test() -> Result<(), ScanFailure> {
        let target =
            std::env::var("CLUTTERHUNTER_TEST_VOLUME").unwrap_or_else(|_| "C:\\".to_owned());
        let output = scan_with_helper(
            &target,
            PathBuf::from(&target),
            "manual-raw-smoke".to_owned(),
            Arc::new(AtomicBool::new(false)),
            &mut |phase, records, bytes, elapsed| {
                println!(
                    "progress phase={phase:?} records={records} bytes={bytes} elapsed_ms={elapsed}"
                );
            },
        )?;

        println!(
            "entries={} scan_ms={} stream_ms={} adopt_ms={} allocated_bytes={} arena_bytes={} helper_peak={} host_peak={}",
            output.arena.entry_count(),
            output.statistics.elapsed_ms,
            output.statistics.stream_ms,
            output.statistics.adopt_ms,
            output.arena.allocated_bytes(),
            output
                .statistics
                .arena_node_bytes
                .saturating_add(output.statistics.arena_name_bytes),
            output.statistics.helper_peak_working_set_bytes,
            output.statistics.host_peak_working_set_bytes,
        );
        assert!(output.arena.entry_count() > 0);
        Ok(())
    }

    #[test]
    #[ignore = "requires Windows elevation and scans the fixture's real NTFS volume"]
    fn elevated_folder_scan_matches_traversal_fixture() -> Result<(), ScanFailure> {
        let fixture = TempScanFixture::new()?;
        let first = fixture.path.join("alpha");
        let second = fixture.path.join("\u{65e5}\u{672c}\u{8a9e}");
        std::fs::create_dir_all(&first).map_err(fixture_error)?;
        std::fs::create_dir_all(&second).map_err(fixture_error)?;
        std::fs::write(first.join("payload.bin"), vec![0xA5; 32 * 1024]).map_err(fixture_error)?;
        std::fs::hard_link(first.join("payload.bin"), second.join("alias.bin"))
            .map_err(fixture_error)?;
        std::fs::write(fixture.path.join("zero.txt"), []).map_err(fixture_error)?;

        let target_path = fixture.path.to_string_lossy().into_owned();
        let raw = scan_with_helper(
            &target_path,
            fixture.path.clone(),
            "differential-raw".to_owned(),
            Arc::new(AtomicBool::new(false)),
            &mut |_, _, _, _| {},
        )?;
        let request = ScanRequest {
            target: ScanTarget {
                id: "differential-fixture".to_owned(),
                kind: ScanTargetKind::Folder,
                display_path: target_path,
                filesystem: Some("NTFS".to_owned()),
                volume_id: None,
                total_bytes: None,
                available_bytes: None,
                fast_scan_available: true,
            },
            preferred_backend: ScanBackend::Traversal,
        };
        let traversal = TraversalBackend.scan(
            request,
            "differential-traversal".to_owned(),
            Arc::new(AtomicBool::new(false)),
            &mut |_| {},
        )?;

        assert_eq!(raw.arena.entry_count(), traversal.arena.entry_count());
        assert_eq!(raw.arena.logical_bytes(), traversal.arena.logical_bytes());
        assert_eq!(
            raw.arena.allocated_bytes(),
            traversal.arena.allocated_bytes()
        );
        assert_eq!(root_names(&raw.arena)?, root_names(&traversal.arena)?);
        Ok(())
    }

    #[test]
    #[ignore = "requires Windows elevation and a real NTFS volume"]
    fn elevated_named_pipe_scan_cancels() {
        let target =
            std::env::var("CLUTTERHUNTER_TEST_VOLUME").unwrap_or_else(|_| "C:\\".to_owned());
        let cancel = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&cancel);
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            trigger.store(true, Ordering::Release);
        });
        let result = scan_with_helper(
            &target,
            PathBuf::from(&target),
            "manual-raw-cancel".to_owned(),
            cancel,
            &mut |_, _, _, _| {},
        );
        let _ = worker.join();
        let error = match result {
            Ok(_) => panic!("the cancelled scan unexpectedly completed"),
            Err(error) => error,
        };

        assert_eq!(error.code, "SCAN_CANCELLED");
    }

    struct TempScanFixture {
        path: PathBuf,
    }

    impl TempScanFixture {
        fn new() -> Result<Self, ScanFailure> {
            let unique = format!(
                "clutterhunter-differential-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| fixture_error(std::io::Error::other(error)))?
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir(&path).map_err(fixture_error)?;
            Ok(Self { path })
        }
    }

    impl Drop for TempScanFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn fixture_error(error: std::io::Error) -> ScanFailure {
        ScanFailure::new(
            "DIFFERENTIAL_FIXTURE_FAILED",
            format!("Could not prepare the differential scanner fixture: {error}"),
            true,
        )
    }

    fn root_names(arena: &ScanArena) -> Result<Vec<String>, ScanFailure> {
        let page = arena.query(&ItemQuery {
            parent_id: None,
            sort: ItemSort::Name,
            direction: SortDirection::Asc,
            cursor: None,
            limit: 100,
            ..ItemQuery::default()
        })?;
        Ok(page.items.into_iter().map(|item| item.name).collect())
    }

    fn stream_root() -> RawArenaNode {
        RawArenaNode {
            name_length: 3,
            parent: RAW_NODE_NO_INDEX,
            first_child: RAW_NODE_NO_INDEX,
            next_sibling: RAW_NODE_NO_INDEX,
            flags: RAW_NODE_FLAG_DIRECTORY,
            ..RawArenaNode::default()
        }
    }

    fn encode_frames(messages: &[HelperMessage]) -> Vec<u8> {
        let mut stream = Vec::new();
        for message in messages {
            let frame =
                bincode::serde::encode_to_vec(message, bincode::config::standard()).unwrap();
            stream.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            stream.extend_from_slice(&frame);
        }
        stream
    }

    fn raw_entry(
        record_id: u64,
        parent_record_id: u64,
        link_index: u32,
        name: &str,
        is_directory: bool,
        allocated_bytes: u64,
    ) -> RawScanEntry {
        RawScanEntry {
            record_id,
            link_index,
            parent_record_id,
            name: name.to_owned(),
            is_directory,
            is_reparse_point: false,
            logical_bytes: allocated_bytes,
            allocated_bytes,
            modified_at_ms: None,
            hard_link_count: 1,
            hard_link_alias: false,
        }
    }
}
