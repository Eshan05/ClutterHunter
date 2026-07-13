// Portions of the raw-volume ingestion design are adapted from eDirStat 2.0.1
// (MIT). See THIRD_PARTY_NOTICES.md at the repository root.

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::io::AsRawHandle as _,
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread,
    time::Instant,
};

use bytemuck::{Pod, Zeroable, cast_slice_mut};
use clutter_protocol::{
    RAW_NODE_FLAG_DIRECTORY, RAW_NODE_FLAG_HARD_LINK_ALIAS, RAW_NODE_FLAG_REPARSE_POINT,
    RAW_NODE_NO_INDEX, RawArenaNode, RawArenaSnapshot, RawScanPhase, RawScanStatistics,
    RawScanWarning,
};
use rayon::prelude::*;
use smallvec::SmallVec;
use windows::Win32::{
    Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        IO::{CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED},
        Ioctl::{FSCTL_QUERY_USN_JOURNAL, USN_JOURNAL_DATA_V0},
        Threading::{CreateEventW, WaitForSingleObject},
    },
};
use windows::core::{HRESULT, PCWSTR};

const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const BUFFER_COUNT: usize = 4;
const PAGE_SIZE: usize = 4096;
const FIRST_NORMAL_RECORD: u64 = 24;
const ROOT_RECORD: u64 = 5;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const JOURNAL_QUERY_TIMEOUT_MS: u32 = 500;
const FILE_REFERENCE_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
const WINDOWS_EPOCH_DIFFERENCE_100NS: u64 = 116_444_736_000_000_000;

pub struct ScanProduct {
    pub arena: RawArenaSnapshot,
    pub statistics: RawScanStatistics,
    pub warnings: Vec<RawScanWarning>,
}

struct RawScanTarget {
    volume_root: String,
    display_path: String,
    components: Vec<String>,
}

#[derive(Clone, Copy)]
struct JournalPosition {
    id: u64,
    next_usn: i64,
}

pub fn scan(
    target: &str,
    is_cancelled: impl Fn() -> bool,
    mut on_progress: impl FnMut(RawScanPhase, u64, u64, u64) -> Result<(), String>,
) -> Result<ScanProduct, String> {
    let started = Instant::now();
    let scan_target = parse_scan_target(target)?;
    on_progress(RawScanPhase::Preparing, 0, 0, elapsed_ms(started))?;
    let volume_path = raw_volume_path(&scan_target.volume_root)?;
    let mut volume = open_volume(&volume_path).map_err(|error| error.to_string())?;
    let journal_start = query_usn_journal(&volume_path);
    let geometry = read_geometry(&mut volume).map_err(|error| error.to_string())?;
    let (runs, mft_length) =
        read_mft_layout(&mut volume, geometry).map_err(|error| error.to_string())?;
    let run_count = runs.len() as u64;
    let max_records = mft_length / geometry.record_size;
    if max_records == 0 || max_records > 50_000_000 {
        return Err("the MFT record count is outside the supported range".to_owned());
    }
    on_progress(
        RawScanPhase::Preparing,
        max_records,
        mft_length,
        elapsed_ms(started),
    )?;
    if is_cancelled() {
        return Err("scan cancelled".to_owned());
    }

    let (empty_sender, empty_receiver) = sync_channel(BUFFER_COUNT);
    for _ in 0..BUFFER_COUNT {
        empty_sender
            .send(vec![AlignedPage::zeroed(); CHUNK_SIZE / PAGE_SIZE])
            .map_err(|error| error.to_string())?;
    }
    let (sender, receiver) = sync_channel::<ChunkMessage>(BUFFER_COUNT);
    let reader = volume;
    let ingest_started = Instant::now();
    let producer = thread::spawn(move || {
        produce_chunks(
            reader,
            runs,
            geometry.cluster_size,
            geometry.record_size,
            mft_length,
            empty_receiver,
            sender,
        );
    });

    let parse_result = consume_chunks(
        receiver,
        empty_sender,
        geometry,
        max_records as usize,
        &is_cancelled,
        &started,
        &mut on_progress,
    );
    let _ = producer.join();
    let (owners, invalid_records, parsed_records, named_streams, attribute_lists) = parse_result?;
    let ingest_ms = elapsed_ms(ingest_started);
    on_progress(
        RawScanPhase::Indexing,
        parsed_records,
        mft_length,
        elapsed_ms(started),
    )?;
    if is_cancelled() {
        return Err("scan cancelled".to_owned());
    }
    let finalize_started = Instant::now();
    let mut product = finish_product(FinishProductInput {
        owners,
        target: &scan_target.volume_root,
        max_records: max_records as usize,
        invalid_records,
        parsed_records,
        named_streams,
        attribute_lists,
        scope: (!scan_target.components.is_empty()).then_some(&scan_target),
    })?;
    product.statistics.finalize_ms = elapsed_ms(finalize_started);
    product.statistics.mft_bytes_read = mft_length;
    product.statistics.mft_data_runs = run_count;
    product.statistics.ingest_ms = ingest_ms;
    product.statistics.elapsed_ms = elapsed_ms(started);
    let journal_end = query_usn_journal(&volume_path);
    record_journal_positions(
        &mut product.statistics,
        journal_start.as_ref().ok().copied(),
        journal_end.as_ref().ok().copied(),
    );
    if journal_start.is_err() || journal_end.is_err() {
        product.warnings.push(RawScanWarning {
            code: "USN_JOURNAL_UNAVAILABLE".to_owned(),
            detail: "The NTFS change journal position could not be captured for this scan"
                .to_owned(),
        });
    }
    if is_cancelled() {
        return Err("scan cancelled".to_owned());
    }
    on_progress(
        RawScanPhase::Finalizing,
        product.statistics.entry_count,
        mft_length,
        product.statistics.elapsed_ms,
    )?;
    Ok(product)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn query_usn_journal(volume_path: &str) -> Result<JournalPosition, String> {
    let volume = open_overlapped_volume(volume_path)
        .map_err(|error| format!("could not open the volume for a journal query: {error}"))?;
    let handle = HANDLE(volume.as_raw_handle());
    let event = JournalEvent(
        unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|error| format!("could not create the journal query event: {error}"))?,
    );
    let mut overlapped = OVERLAPPED {
        hEvent: event.0,
        ..OVERLAPPED::default()
    };
    let mut data = USN_JOURNAL_DATA_V0::default();
    let mut returned = 0u32;
    let output_size = u32::try_from(std::mem::size_of::<USN_JOURNAL_DATA_V0>())
        .map_err(|_| "the USN journal response size overflowed".to_owned())?;
    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(std::ptr::addr_of_mut!(data).cast()),
            output_size,
            Some(&mut returned),
            Some(&mut overlapped),
        )
    };
    if let Err(error) = result {
        if error.code() != HRESULT::from_win32(ERROR_IO_PENDING.0) {
            return Err(format!("could not query the NTFS change journal: {error}"));
        }
        match unsafe { WaitForSingleObject(event.0, JOURNAL_QUERY_TIMEOUT_MS) } {
            WAIT_OBJECT_0 => {
                unsafe { GetOverlappedResult(handle, &overlapped, &mut returned, false) }.map_err(
                    |error| format!("could not finish the NTFS change journal query: {error}"),
                )?
            }
            WAIT_TIMEOUT => {
                let _ = unsafe { CancelIoEx(handle, Some(&overlapped)) };
                let _ = unsafe { WaitForSingleObject(event.0, u32::MAX) };
                return Err("the NTFS change journal query timed out".to_owned());
            }
            WAIT_FAILED => return Err("waiting for the NTFS change journal failed".to_owned()),
            _ => {
                return Err("the NTFS change journal returned an unexpected wait status".to_owned());
            }
        }
    }
    if returned < output_size {
        return Err("the NTFS change journal returned an incomplete response".to_owned());
    }
    Ok(JournalPosition {
        id: data.UsnJournalID,
        next_usn: data.NextUsn,
    })
}

struct JournalEvent(HANDLE);

impl Drop for JournalEvent {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn record_journal_positions(
    statistics: &mut RawScanStatistics,
    start: Option<JournalPosition>,
    end: Option<JournalPosition>,
) {
    if let Some(start) = start {
        statistics.journal_id_start = Some(start.id);
        statistics.journal_next_usn_start = Some(start.next_usn);
    }
    if let Some(end) = end {
        statistics.journal_id_end = Some(end.id);
        statistics.journal_next_usn_end = Some(end.next_usn);
    }
}

#[derive(Clone, Copy)]
struct VolumeGeometry {
    sector_size: usize,
    cluster_size: u64,
    record_size: u64,
    mft_offset: u64,
}

#[derive(Clone)]
struct DataRun {
    length_clusters: u64,
    lcn: Option<i64>,
}

enum ChunkMessage {
    Data(MftChunk),
    Error(String),
}

struct MftChunk {
    buffer: Vec<AlignedPage>,
    bytes_read: usize,
    start_record_id: u64,
}

#[repr(C, align(4096))]
#[derive(Clone, Copy, Pod, Zeroable)]
struct AlignedPage {
    bytes: [u8; PAGE_SIZE],
}

#[derive(Default)]
struct OwnerAccumulator {
    seen_base: bool,
    is_directory: bool,
    is_reparse_point: bool,
    modified_at_ms: Option<i64>,
    link_count: u32,
    logical_bytes: u64,
    allocated_bytes: u64,
    fallback_logical_bytes: u64,
    fallback_allocated_bytes: u64,
    links: SmallVec<[LinkCandidate; 1]>,
}

struct RecordFragment {
    owner_id: u64,
    is_base: bool,
    is_directory: bool,
    is_reparse_point: bool,
    modified_at_ms: Option<i64>,
    link_count: u32,
    logical_bytes: u64,
    allocated_bytes: u64,
    fallback_logical_bytes: u64,
    fallback_allocated_bytes: u64,
    links: SmallVec<[LinkCandidate; 1]>,
    named_streams: u64,
    has_attribute_list: bool,
}

enum ParsedRecord {
    Valid(RecordFragment),
    Unused,
    Invalid,
}

#[derive(Debug)]
struct LinkCandidate {
    parent_record_id: u64,
    name: String,
    namespace: u8,
}

struct ParsedAttribute<'a> {
    kind: u32,
    non_resident: bool,
    name_length: u8,
    bytes: &'a [u8],
}

struct AttributeIter<'a> {
    record: &'a [u8],
    offset: usize,
    used: usize,
    done: bool,
}

fn open_volume(path: &str) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options
            .share_mode(7)
            .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
    }
    options.open(path)
}

fn open_overlapped_volume(path: &str) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.share_mode(7).custom_flags(FILE_FLAG_OVERLAPPED);
    }
    options.open(path)
}

fn read_geometry(volume: &mut File) -> std::io::Result<VolumeGeometry> {
    let mut boot = [0u8; 512];
    volume.seek(SeekFrom::Start(0))?;
    volume.read_exact(&mut boot)?;
    if &boot[3..11] != b"NTFS    " || boot[510] != 0x55 || boot[511] != 0xAA {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the target does not contain a valid NTFS boot sector",
        ));
    }

    let sector_size = usize::from(read_u16(&boot, 0x0B).unwrap_or(0));
    let sectors_per_cluster = u64::from(boot[0x0D]);
    if !matches!(sector_size, 512 | 1024 | 2048 | 4096) || sectors_per_cluster == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the NTFS sector or cluster geometry is invalid",
        ));
    }
    let cluster_size = (sector_size as u64)
        .checked_mul(sectors_per_cluster)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "cluster size overflow")
        })?;
    let record_size_marker = boot[0x40] as i8;
    let record_size = if record_size_marker < 0 {
        1u64.checked_shl(u32::from(record_size_marker.unsigned_abs()))
    } else {
        cluster_size.checked_mul(record_size_marker as u64)
    }
    .filter(|size| *size >= 512 && *size <= 64 * 1024)
    .ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid MFT record size")
    })?;
    let mft_lcn = read_u64(&boot, 0x30).unwrap_or(0);
    let mft_offset = mft_lcn.checked_mul(cluster_size).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "MFT offset overflow")
    })?;

    Ok(VolumeGeometry {
        sector_size,
        cluster_size,
        record_size,
        mft_offset,
    })
}

fn read_mft_layout(
    volume: &mut File,
    geometry: VolumeGeometry,
) -> std::io::Result<(Vec<DataRun>, u64)> {
    let mut record = vec![0u8; geometry.record_size as usize];
    volume.seek(SeekFrom::Start(geometry.mft_offset))?;
    volume.read_exact(&mut record)?;
    if !apply_fixup(&mut record, geometry.sector_size) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the MFT root record failed its update-sequence fixup",
        ));
    }

    for attribute in parse_attributes(&record) {
        if attribute.kind != 0x80 || !attribute.non_resident || attribute.name_length != 0 {
            continue;
        }
        let run_offset = usize::from(read_u16(attribute.bytes, 32).unwrap_or(0));
        let data_size = read_u64(attribute.bytes, 48).unwrap_or(0);
        if run_offset >= attribute.bytes.len() || data_size == 0 {
            continue;
        }
        let runs = decode_data_runs(&attribute.bytes[run_offset..]);
        if !runs.is_empty() {
            return Ok((runs, data_size));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the MFT data-run map could not be resolved",
    ))
}

fn produce_chunks(
    mut volume: File,
    runs: Vec<DataRun>,
    cluster_size: u64,
    record_size: u64,
    mft_length: u64,
    empty_receiver: Receiver<Vec<AlignedPage>>,
    sender: SyncSender<ChunkMessage>,
) {
    let mut logical_offset = 0u64;
    for run in runs {
        if logical_offset >= mft_length {
            break;
        }
        let run_bytes = run.length_clusters.saturating_mul(cluster_size);
        let mut remaining = run_bytes.min(mft_length - logical_offset);
        if run.lcn.is_none() {
            logical_offset = logical_offset.saturating_add(remaining);
            continue;
        }
        let Some(offset) = run
            .lcn
            .filter(|value| *value >= 0)
            .and_then(|value| (value as u64).checked_mul(cluster_size))
        else {
            let _ = sender.send(ChunkMessage::Error(
                "an MFT data run has an invalid disk offset".to_owned(),
            ));
            return;
        };
        if let Err(error) = volume.seek(SeekFrom::Start(offset)) {
            let _ = sender.send(ChunkMessage::Error(error.to_string()));
            return;
        }

        while remaining >= record_size {
            let requested = remaining.min(CHUNK_SIZE as u64);
            let aligned = requested - (requested % record_size);
            if aligned == 0 {
                break;
            }
            let mut buffer = match empty_receiver.recv() {
                Ok(buffer) => buffer,
                Err(_) => return,
            };
            let read_size = (aligned as usize).div_ceil(PAGE_SIZE) * PAGE_SIZE;
            let bytes = cast_slice_mut(&mut buffer);
            if let Err(error) = volume.read_exact(&mut bytes[..read_size]) {
                let _ = sender.send(ChunkMessage::Error(error.to_string()));
                return;
            }
            let chunk = MftChunk {
                buffer,
                bytes_read: aligned as usize,
                start_record_id: logical_offset / record_size,
            };
            if sender.send(ChunkMessage::Data(chunk)).is_err() {
                return;
            }
            logical_offset = logical_offset.saturating_add(aligned);
            remaining -= aligned;
        }
    }
}

type OwnerRow = (u64, OwnerAccumulator);
type ConsumeProduct = (Vec<OwnerRow>, u64, u64, u64, u64);

fn consume_chunks(
    receiver: Receiver<ChunkMessage>,
    empty_sender: SyncSender<Vec<AlignedPage>>,
    geometry: VolumeGeometry,
    max_records: usize,
    is_cancelled: &dyn Fn() -> bool,
    started: &Instant,
    on_progress: &mut dyn FnMut(RawScanPhase, u64, u64, u64) -> Result<(), String>,
) -> Result<ConsumeProduct, String> {
    let mut owner_indices = vec![u32::MAX; max_records];
    let mut owners = Vec::<OwnerRow>::with_capacity(max_records.min(8_000_000));
    let mut invalid_records = 0u64;
    let mut parsed_records = 0u64;
    let mut named_streams = 0u64;
    let mut attribute_lists = 0u64;
    let mut mft_bytes_read = 0u64;

    while let Ok(message) = receiver.recv() {
        if is_cancelled() {
            return Err("scan cancelled".to_owned());
        }
        let mut chunk = match message {
            ChunkMessage::Data(chunk) => chunk,
            ChunkMessage::Error(error) => return Err(error),
        };
        let record_size = geometry.record_size as usize;
        let bytes = cast_slice_mut(&mut chunk.buffer);
        let fragments: Vec<_> = bytes[..chunk.bytes_read]
            .par_chunks_exact_mut(record_size)
            .enumerate()
            .map(|(index, bytes)| {
                parse_record(
                    chunk.start_record_id.saturating_add(index as u64),
                    bytes,
                    geometry.sector_size,
                )
            })
            .collect();
        mft_bytes_read = mft_bytes_read.saturating_add(chunk.bytes_read as u64);
        let _ = empty_sender.send(chunk.buffer);

        for fragment in fragments {
            let fragment = match fragment {
                ParsedRecord::Valid(fragment) => fragment,
                ParsedRecord::Unused => continue,
                ParsedRecord::Invalid => {
                    invalid_records = invalid_records.saturating_add(1);
                    continue;
                }
            };
            parsed_records = parsed_records.saturating_add(1);
            named_streams = named_streams.saturating_add(fragment.named_streams);
            attribute_lists =
                attribute_lists.saturating_add(u64::from(fragment.has_attribute_list));
            if fragment.owner_id < FIRST_NORMAL_RECORD {
                continue;
            }
            let owner_id = fragment.owner_id as usize;
            let Some(owner_index) = owner_indices.get_mut(owner_id) else {
                invalid_records = invalid_records.saturating_add(1);
                continue;
            };
            let owner_index = if *owner_index == u32::MAX {
                let index = u32::try_from(owners.len())
                    .map_err(|_| "the MFT owner index exceeded its supported range")?;
                *owner_index = index;
                owners.push((fragment.owner_id, OwnerAccumulator::default()));
                index
            } else {
                *owner_index
            };
            let owner = &mut owners[owner_index as usize].1;
            owner.seen_base |= fragment.is_base;
            if fragment.is_base {
                owner.is_directory = fragment.is_directory;
                owner.link_count = owner.link_count.max(fragment.link_count);
                owner.modified_at_ms = fragment.modified_at_ms.or(owner.modified_at_ms);
            }
            owner.is_reparse_point |= fragment.is_reparse_point;
            owner.logical_bytes = owner.logical_bytes.max(fragment.logical_bytes);
            owner.allocated_bytes = owner.allocated_bytes.max(fragment.allocated_bytes);
            owner.fallback_logical_bytes = owner
                .fallback_logical_bytes
                .max(fragment.fallback_logical_bytes);
            owner.fallback_allocated_bytes = owner
                .fallback_allocated_bytes
                .max(fragment.fallback_allocated_bytes);
            owner.links.extend(fragment.links);
        }
        on_progress(
            RawScanPhase::Enumerating,
            parsed_records,
            mft_bytes_read,
            elapsed_ms(*started),
        )?;
    }

    Ok((
        owners,
        invalid_records,
        parsed_records,
        named_streams,
        attribute_lists,
    ))
}

fn parse_record(record_id: u64, record: &mut [u8], sector_size: usize) -> ParsedRecord {
    if record.get(..4) != Some(b"FILE") {
        return ParsedRecord::Unused;
    }
    if !apply_fixup(record, sector_size) {
        return ParsedRecord::Invalid;
    }
    let Some(flags) = read_u16(record, 22) else {
        return ParsedRecord::Invalid;
    };
    if flags & 1 == 0 {
        return ParsedRecord::Unused;
    }
    let Some(base_reference) = read_u64(record, 32).map(|value| value & FILE_REFERENCE_MASK) else {
        return ParsedRecord::Invalid;
    };
    let is_base = base_reference == 0;
    let owner_id = if is_base { record_id } else { base_reference };
    let mut links = SmallVec::new();
    let mut logical_bytes = 0u64;
    let mut allocated_bytes = 0u64;
    let mut fallback_logical_bytes = 0u64;
    let mut fallback_allocated_bytes = 0u64;
    let mut modified_at_ms = None;
    let mut is_reparse_point = false;
    let mut named_streams = 0u64;
    let mut has_attribute_list = false;

    for attribute in parse_attributes(record) {
        match attribute.kind {
            0x10 if !attribute.non_resident => {
                if let Some(value) = resident_value(attribute.bytes) {
                    modified_at_ms = read_u64(value, 8).and_then(nt_time_to_unix_ms);
                    is_reparse_point |= read_u32(value, 32).is_some_and(|attrs| attrs & 0x400 != 0);
                }
            }
            0x20 => has_attribute_list = true,
            0x30 if !attribute.non_resident => {
                if let Some(value) = resident_value(attribute.bytes)
                    && let Some(link) = parse_file_name(value)
                {
                    fallback_logical_bytes =
                        fallback_logical_bytes.max(read_u64(value, 48).unwrap_or(0));
                    fallback_allocated_bytes =
                        fallback_allocated_bytes.max(read_u64(value, 40).unwrap_or(0));
                    is_reparse_point |= read_u32(value, 56).is_some_and(|attrs| attrs & 0x400 != 0);
                    links.push(link);
                }
            }
            0x80 if attribute.name_length > 0 => {
                named_streams = named_streams.saturating_add(1);
            }
            0x80 if attribute.non_resident => {
                let lowest_vcn = read_u64(attribute.bytes, 16).unwrap_or(u64::MAX);
                if lowest_vcn == 0 {
                    logical_bytes = logical_bytes.max(read_u64(attribute.bytes, 48).unwrap_or(0));
                    allocated_bytes =
                        allocated_bytes.max(read_u64(attribute.bytes, 40).unwrap_or(0));
                }
            }
            0x80 => {
                logical_bytes =
                    logical_bytes.max(u64::from(read_u32(attribute.bytes, 16).unwrap_or(0)));
            }
            _ => {}
        }
    }

    ParsedRecord::Valid(RecordFragment {
        owner_id,
        is_base,
        is_directory: flags & 2 != 0,
        is_reparse_point,
        modified_at_ms,
        link_count: u32::from(read_u16(record, 18).unwrap_or(0)),
        logical_bytes,
        allocated_bytes,
        fallback_logical_bytes,
        fallback_allocated_bytes,
        links,
        named_streams,
        has_attribute_list,
    })
}

struct FinishProductInput<'a> {
    owners: Vec<OwnerRow>,
    target: &'a str,
    max_records: usize,
    invalid_records: u64,
    parsed_records: u64,
    named_streams: u64,
    attribute_lists: u64,
    scope: Option<&'a RawScanTarget>,
}

fn finish_product(input: FinishProductInput<'_>) -> Result<ScanProduct, String> {
    let FinishProductInput {
        mut owners,
        target,
        max_records,
        invalid_records,
        parsed_records,
        named_streams,
        attribute_lists,
        scope,
    } = input;
    owners
        .par_iter_mut()
        .for_each(|(_, owner)| normalize_links(&mut owner.links));
    let entry_capacity: usize = owners.iter().map(|(_, owner)| owner.links.len()).sum();
    let mut nodes = Vec::with_capacity(entry_capacity.saturating_add(1));
    let mut names = Vec::new();
    let mut parent_records = Vec::with_capacity(entry_capacity.saturating_add(1));
    let mut record_ids = scope.map(|_| Vec::with_capacity(entry_capacity.saturating_add(1)));
    let mut physical_allocations =
        scope.map(|_| Vec::with_capacity(entry_capacity.saturating_add(1)));
    let mut directory_nodes = vec![RAW_NODE_NO_INDEX; max_records];
    names.extend_from_slice(target.as_bytes());
    nodes.push(RawArenaNode {
        name_length: target.len() as u32,
        parent: RAW_NODE_NO_INDEX,
        first_child: RAW_NODE_NO_INDEX,
        next_sibling: RAW_NODE_NO_INDEX,
        flags: RAW_NODE_FLAG_DIRECTORY,
        ..RawArenaNode::default()
    });
    parent_records.push(ROOT_RECORD);
    if let Some(record_ids) = &mut record_ids {
        record_ids.push(ROOT_RECORD);
    }
    if let Some(allocations) = &mut physical_allocations {
        allocations.push(0);
    }
    if let Some(root) = directory_nodes.get_mut(ROOT_RECORD as usize) {
        *root = 0;
    }
    let mut statistics = RawScanStatistics {
        mft_record_count: parsed_records,
        named_data_streams: named_streams,
        attribute_list_records: attribute_lists,
        ..RawScanStatistics::default()
    };
    let mut missing_base_records = 0u64;

    for (record_id, owner) in owners {
        if !owner.seen_base || owner.links.is_empty() {
            missing_base_records = missing_base_records.saturating_add(1);
            continue;
        }
        if owner.links.is_empty() {
            continue;
        }
        let logical_bytes = owner.logical_bytes.max(owner.fallback_logical_bytes);
        let allocated_bytes = if owner.is_directory {
            0
        } else {
            owner.allocated_bytes.max(owner.fallback_allocated_bytes)
        };
        let hard_link_count = owner.link_count.max(owner.links.len() as u32);
        statistics.hard_linked_records = statistics
            .hard_linked_records
            .saturating_add(u64::from(hard_link_count > 1));
        statistics.reparse_points = statistics
            .reparse_points
            .saturating_add(u64::from(owner.is_reparse_point));
        if owner.is_directory {
            statistics.directory_count = statistics.directory_count.saturating_add(1);
        } else {
            statistics.file_count = statistics.file_count.saturating_add(1);
        }

        for (link_index, link) in owner.links.into_iter().enumerate() {
            let hard_link_alias = link_index > 0 && !owner.is_directory;
            let node_index = u32::try_from(nodes.len())
                .map_err(|_| "the raw arena exceeded its 32-bit node limit")?;
            let name_offset = u32::try_from(names.len())
                .map_err(|_| "the raw arena name pool exceeded its 32-bit limit")?;
            let name_length = u32::try_from(link.name.len())
                .map_err(|_| "an MFT filename exceeded its supported length")?;
            names.extend_from_slice(link.name.as_bytes());
            let mut flags = 0u16;
            if owner.is_directory {
                flags |= RAW_NODE_FLAG_DIRECTORY;
            }
            if owner.is_reparse_point {
                flags |= RAW_NODE_FLAG_REPARSE_POINT;
            }
            if hard_link_alias {
                flags |= RAW_NODE_FLAG_HARD_LINK_ALIAS;
            }
            let node_allocated_bytes = if hard_link_alias { 0 } else { allocated_bytes };
            statistics.logical_bytes = statistics.logical_bytes.saturating_add(logical_bytes);
            statistics.allocated_bytes = statistics
                .allocated_bytes
                .saturating_add(node_allocated_bytes);
            nodes.push(RawArenaNode {
                name_offset,
                name_length,
                parent: RAW_NODE_NO_INDEX,
                first_child: RAW_NODE_NO_INDEX,
                next_sibling: RAW_NODE_NO_INDEX,
                child_count: 0,
                logical_bytes,
                allocated_bytes: node_allocated_bytes,
                modified_at_ms: owner.modified_at_ms.unwrap_or(-1),
                hard_link_count,
                flags,
                reserved: 0,
            });
            parent_records.push(link.parent_record_id);
            if let Some(record_ids) = &mut record_ids {
                record_ids.push(record_id);
            }
            if let Some(allocations) = &mut physical_allocations {
                allocations.push(allocated_bytes);
            }
            if owner.is_directory
                && let Some(slot) = directory_nodes.get_mut(record_id as usize)
                && *slot == RAW_NODE_NO_INDEX
            {
                *slot = node_index;
            }
        }
    }

    statistics.entry_count = nodes.len().saturating_sub(1) as u64;
    let mut warnings = Vec::new();
    if invalid_records > 0 {
        warnings.push(RawScanWarning {
            code: "INVALID_MFT_RECORDS".to_owned(),
            detail: format!("{invalid_records} allocated MFT slots could not be decoded"),
        });
    }
    if missing_base_records > 0 {
        warnings.push(RawScanWarning {
            code: "ORPHAN_MFT_EXTENTS".to_owned(),
            detail: format!("{missing_base_records} extension records had no usable base record"),
        });
    }
    let orphaned = build_hierarchy(&mut nodes, &parent_records, &directory_nodes);
    if orphaned > 0 {
        warnings.push(RawScanWarning {
            code: "ORPHAN_MFT_PARENT".to_owned(),
            detail: format!(
                "{orphaned} MFT entries had invalid or cyclic parents and were attached to the scan root"
            ),
        });
    }

    let mut arena = RawArenaSnapshot { nodes, names };
    if let Some(scope) = scope {
        arena = select_subtree(
            arena,
            scope,
            record_ids.as_deref().unwrap_or_default(),
            physical_allocations.as_deref().unwrap_or_default(),
        )?;
        rescope_statistics(&mut statistics, &arena);
    }
    statistics.arena_node_bytes = arena
        .nodes
        .capacity()
        .saturating_mul(std::mem::size_of::<RawArenaNode>())
        as u64;
    statistics.arena_name_bytes = arena.names.capacity() as u64;

    Ok(ScanProduct {
        arena,
        statistics,
        warnings,
    })
}

fn select_subtree(
    source: RawArenaSnapshot,
    target: &RawScanTarget,
    record_ids: &[u64],
    physical_allocations: &[u64],
) -> Result<RawArenaSnapshot, String> {
    if source.nodes.len() != record_ids.len() || source.nodes.len() != physical_allocations.len() {
        return Err("the raw subtree metadata was incomplete".to_owned());
    }

    let mut scope_root = 0u32;
    for component in &target.components {
        let mut child = source.nodes[scope_root as usize].first_child;
        let mut matched = None;
        while child != RAW_NODE_NO_INDEX {
            let node = &source.nodes[child as usize];
            if node.is_directory() && names_equal(arena_name(&source, child), component) {
                matched = Some(child);
                break;
            }
            child = node.next_sibling;
        }
        scope_root = matched.ok_or_else(|| {
            format!(
                "the selected folder was not found in the MFT hierarchy: {}",
                target.display_path
            )
        })?;
    }

    let mut selected = Vec::new();
    let mut stack = vec![scope_root];
    while let Some(index) = stack.pop() {
        selected.push(index);
        let mut children = Vec::new();
        let mut child = source.nodes[index as usize].first_child;
        while child != RAW_NODE_NO_INDEX {
            children.push(child);
            child = source.nodes[child as usize].next_sibling;
        }
        stack.extend(children.into_iter().rev());
    }

    let mut old_to_new = vec![RAW_NODE_NO_INDEX; source.nodes.len()];
    for (new_index, old_index) in selected.iter().copied().enumerate() {
        old_to_new[old_index as usize] = new_index as u32;
    }
    let mut nodes = Vec::with_capacity(selected.len());
    let mut names = Vec::new();
    let mut seen_records = HashSet::new();
    for (new_index, old_index) in selected.iter().copied().enumerate() {
        let mut node = source.nodes[old_index as usize];
        let name = if new_index == 0 {
            target.display_path.as_str()
        } else {
            arena_name(&source, old_index)
        };
        node.name_offset = u32::try_from(names.len())
            .map_err(|_| "the scoped raw name pool exceeded its 32-bit limit")?;
        node.name_length = u32::try_from(name.len())
            .map_err(|_| "a scoped raw filename exceeded its supported length")?;
        names.extend_from_slice(name.as_bytes());
        node.parent = RAW_NODE_NO_INDEX;
        node.first_child = RAW_NODE_NO_INDEX;
        node.next_sibling = RAW_NODE_NO_INDEX;
        node.child_count = 0;
        if node.is_directory() {
            node.logical_bytes = 0;
            node.allocated_bytes = 0;
        } else if seen_records.insert(record_ids[old_index as usize]) {
            node.allocated_bytes = physical_allocations[old_index as usize];
            node.flags &= !RAW_NODE_FLAG_HARD_LINK_ALIAS;
        } else {
            node.allocated_bytes = 0;
            node.flags |= RAW_NODE_FLAG_HARD_LINK_ALIAS;
        }
        nodes.push(node);
    }

    let mut last_child = vec![RAW_NODE_NO_INDEX; nodes.len()];
    for new_index in 1..nodes.len() {
        let old_parent = source.nodes[selected[new_index] as usize].parent;
        let parent = old_to_new
            .get(old_parent as usize)
            .copied()
            .filter(|index| *index != RAW_NODE_NO_INDEX)
            .ok_or_else(|| "a scoped raw node had no selected parent".to_owned())?;
        nodes[new_index].parent = parent;
        let previous = last_child[parent as usize];
        if previous == RAW_NODE_NO_INDEX {
            nodes[parent as usize].first_child = new_index as u32;
        } else {
            nodes[previous as usize].next_sibling = new_index as u32;
        }
        last_child[parent as usize] = new_index as u32;
        nodes[parent as usize].child_count = nodes[parent as usize].child_count.saturating_add(1);
    }
    for index in (1..nodes.len()).rev() {
        let parent = nodes[index].parent as usize;
        nodes[parent].logical_bytes = nodes[parent]
            .logical_bytes
            .saturating_add(nodes[index].logical_bytes);
        nodes[parent].allocated_bytes = nodes[parent]
            .allocated_bytes
            .saturating_add(nodes[index].allocated_bytes);
    }

    let arena = RawArenaSnapshot { nodes, names };
    arena.validate().map_err(str::to_owned)?;
    Ok(arena)
}

fn rescope_statistics(statistics: &mut RawScanStatistics, arena: &RawArenaSnapshot) {
    statistics.entry_count = arena.nodes.len().saturating_sub(1) as u64;
    statistics.file_count = 0;
    statistics.directory_count = 0;
    statistics.logical_bytes = 0;
    statistics.allocated_bytes = 0;
    statistics.hard_linked_records = 0;
    statistics.reparse_points = 0;
    for node in arena.nodes.iter().skip(1) {
        if node.is_directory() {
            statistics.directory_count = statistics.directory_count.saturating_add(1);
        } else {
            statistics.file_count = statistics.file_count.saturating_add(1);
            statistics.logical_bytes = statistics.logical_bytes.saturating_add(node.logical_bytes);
            statistics.allocated_bytes = statistics
                .allocated_bytes
                .saturating_add(node.allocated_bytes);
            statistics.hard_linked_records = statistics.hard_linked_records.saturating_add(
                u64::from(node.hard_link_count > 1 && !node.is_hard_link_alias()),
            );
        }
        statistics.reparse_points = statistics
            .reparse_points
            .saturating_add(u64::from(node.is_reparse_point()));
    }
}

fn arena_name(arena: &RawArenaSnapshot, index: u32) -> &str {
    let node = &arena.nodes[index as usize];
    let start = node.name_offset as usize;
    let end = start.saturating_add(node.name_length as usize);
    std::str::from_utf8(arena.names.get(start..end).unwrap_or_default()).unwrap_or("")
}

fn names_equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

fn build_hierarchy(
    nodes: &mut [RawArenaNode],
    parent_records: &[u64],
    directory_nodes: &[u32],
) -> u64 {
    let mut parents = vec![0u32; nodes.len()];
    let mut orphaned = 0u64;

    for (index, parent_slot) in parents.iter_mut().enumerate().skip(1) {
        let parent = parent_records
            .get(index)
            .and_then(|record| directory_nodes.get(*record as usize))
            .copied()
            .filter(|parent| *parent != RAW_NODE_NO_INDEX && *parent as usize != index)
            .unwrap_or_else(|| {
                orphaned = orphaned.saturating_add(1);
                0
            });
        *parent_slot = parent;
    }

    let mut states = vec![0u8; nodes.len()];
    states[0] = 2;
    let mut path = Vec::new();
    for start in 1..nodes.len() {
        if states[start] != 0 {
            continue;
        }
        path.clear();
        let mut current = start;
        while current != 0 && states[current] == 0 {
            states[current] = 1;
            path.push(current);
            current = parents[current] as usize;
        }
        if current != 0 && states[current] == 1 {
            let cycle_start = path.iter().position(|index| *index == current).unwrap_or(0);
            parents[current] = 0;
            orphaned = orphaned.saturating_add((path.len() - cycle_start) as u64);
        }
        for index in path.iter().rev().copied() {
            states[index] = 2;
        }
    }

    let mut last_child = vec![RAW_NODE_NO_INDEX; nodes.len()];
    let mut directory_children = vec![0u32; nodes.len()];
    for node in nodes.iter_mut() {
        node.first_child = RAW_NODE_NO_INDEX;
        node.next_sibling = RAW_NODE_NO_INDEX;
        node.child_count = 0;
    }
    for child_index in 1..nodes.len() {
        let parent_index = parents[child_index] as usize;
        nodes[child_index].parent = parents[child_index];
        let previous = last_child[parent_index];
        if previous == RAW_NODE_NO_INDEX {
            nodes[parent_index].first_child = child_index as u32;
        } else {
            nodes[previous as usize].next_sibling = child_index as u32;
        }
        last_child[parent_index] = child_index as u32;
        nodes[parent_index].child_count = nodes[parent_index].child_count.saturating_add(1);
        if nodes[child_index].is_directory() {
            directory_children[parent_index] = directory_children[parent_index].saturating_add(1);
        }
    }
    nodes[0].parent = RAW_NODE_NO_INDEX;

    for child_index in 1..nodes.len() {
        if nodes[child_index].is_directory() {
            continue;
        }
        let parent_index = nodes[child_index].parent as usize;
        nodes[parent_index].logical_bytes = nodes[parent_index]
            .logical_bytes
            .saturating_add(nodes[child_index].logical_bytes);
        nodes[parent_index].allocated_bytes = nodes[parent_index]
            .allocated_bytes
            .saturating_add(nodes[child_index].allocated_bytes);
    }

    let mut queue = Vec::with_capacity(nodes.len() / 4);
    queue.extend(
        directory_children
            .iter()
            .enumerate()
            .filter_map(|(index, count)| {
                (nodes[index].is_directory() && *count == 0).then_some(index as u32)
            }),
    );
    let mut cursor = 0usize;
    while cursor < queue.len() {
        let child_index = queue[cursor] as usize;
        cursor += 1;
        if child_index == 0 {
            continue;
        }
        let parent_index = nodes[child_index].parent as usize;
        nodes[parent_index].logical_bytes = nodes[parent_index]
            .logical_bytes
            .saturating_add(nodes[child_index].logical_bytes);
        nodes[parent_index].allocated_bytes = nodes[parent_index]
            .allocated_bytes
            .saturating_add(nodes[child_index].allocated_bytes);
        directory_children[parent_index] = directory_children[parent_index].saturating_sub(1);
        if directory_children[parent_index] == 0 {
            queue.push(parent_index as u32);
        }
    }

    orphaned
}

fn normalize_links(links: &mut SmallVec<[LinkCandidate; 1]>) {
    if links.len() <= 1 {
        return;
    }
    let has_long_name = links.iter().any(|link| link.namespace != 2);
    if has_long_name {
        links.retain(|link| link.namespace != 2);
    }
    links.sort_unstable_by(|left, right| {
        left.parent_record_id
            .cmp(&right.parent_record_id)
            .then_with(|| left.name.cmp(&right.name))
    });
    links.dedup_by(|left, right| {
        left.parent_record_id == right.parent_record_id && left.name == right.name
    });
}

fn parse_file_name(value: &[u8]) -> Option<LinkCandidate> {
    let name_length = usize::from(*value.get(64)?);
    let namespace = *value.get(65)?;
    let name_bytes = name_length.checked_mul(2)?;
    let end = 66usize.checked_add(name_bytes)?;
    let encoded = value.get(66..end)?;
    let mut ascii = [0u8; 255];
    let mut is_ascii = true;
    for (index, bytes) in encoded.chunks_exact(2).enumerate() {
        if bytes[1] != 0 || !bytes[0].is_ascii() {
            is_ascii = false;
            break;
        }
        ascii[index] = bytes[0];
    }
    let name = if is_ascii {
        String::from_utf8_lossy(&ascii[..name_length]).into_owned()
    } else {
        let mut wide = [0u16; 255];
        for (index, bytes) in encoded.chunks_exact(2).enumerate() {
            wide[index] = u16::from_le_bytes([bytes[0], bytes[1]]);
        }
        String::from_utf16_lossy(&wide[..name_length])
    };
    if name.is_empty() {
        return None;
    }
    Some(LinkCandidate {
        parent_record_id: read_u64(value, 0)? & FILE_REFERENCE_MASK,
        name,
        namespace,
    })
}

fn parse_attributes(record: &[u8]) -> AttributeIter<'_> {
    let offset = read_u16(record, 20).map_or(record.len(), usize::from);
    let used = read_u32(record, 24)
        .map_or(record.len(), |value| value as usize)
        .min(record.len());
    AttributeIter {
        record,
        offset,
        used,
        done: offset > used,
    }
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = ParsedAttribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset.saturating_add(16) > self.used {
            return None;
        }
        let kind = read_u32(self.record, self.offset).unwrap_or(u32::MAX);
        if kind == u32::MAX {
            self.done = true;
            return None;
        }
        let length = read_u32(self.record, self.offset + 4).unwrap_or(0) as usize;
        let Some(end) = self.offset.checked_add(length) else {
            self.done = true;
            return None;
        };
        if length < 16 || end > self.used {
            self.done = true;
            return None;
        }
        let attribute = ParsedAttribute {
            kind,
            non_resident: self.record[self.offset + 8] != 0,
            name_length: self.record[self.offset + 9],
            bytes: &self.record[self.offset..end],
        };
        self.offset = end;
        Some(attribute)
    }
}

fn resident_value(attribute: &[u8]) -> Option<&[u8]> {
    let length = read_u32(attribute, 16)? as usize;
    let offset = usize::from(read_u16(attribute, 20)?);
    let end = offset.checked_add(length)?;
    attribute.get(offset..end)
}

fn apply_fixup(record: &mut [u8], sector_size: usize) -> bool {
    if record.len() < 24 || &record[..4] != b"FILE" || sector_size < 2 {
        return false;
    }
    let Some(sequence_offset) = read_u16(record, 4).map(usize::from) else {
        return false;
    };
    let Some(sequence_count) = read_u16(record, 6).map(usize::from) else {
        return false;
    };
    let Some(sequence_end) = sequence_offset.checked_add(sequence_count.saturating_mul(2)) else {
        return false;
    };
    if sequence_count < 2 || sequence_end > record.len() || sequence_offset + 2 > record.len() {
        return false;
    }
    let update_sequence = [record[sequence_offset], record[sequence_offset + 1]];
    for index in 1..sequence_count {
        let Some(sector_end) = index
            .checked_mul(sector_size)
            .and_then(|value| value.checked_sub(2))
        else {
            return false;
        };
        let replacement = sequence_offset + index * 2;
        if sector_end + 2 > record.len() || replacement + 2 > sequence_end {
            return false;
        }
        if record[sector_end..sector_end + 2] != update_sequence {
            return false;
        }
        record[sector_end] = record[replacement];
        record[sector_end + 1] = record[replacement + 1];
    }
    true
}

fn decode_data_runs(mut bytes: &[u8]) -> Vec<DataRun> {
    let mut result = Vec::new();
    let mut previous_lcn = 0i64;
    while let Some((&descriptor, remaining)) = bytes.split_first() {
        bytes = remaining;
        if descriptor == 0 {
            break;
        }
        let length_size = usize::from(descriptor & 0x0F);
        let offset_size = usize::from(descriptor >> 4);
        if length_size == 0
            || length_size > 8
            || offset_size > 8
            || bytes.len() < length_size + offset_size
        {
            break;
        }
        let length = unsigned_le(&bytes[..length_size]);
        bytes = &bytes[length_size..];
        let lcn = if offset_size == 0 {
            None
        } else {
            let delta = signed_le(&bytes[..offset_size]);
            bytes = &bytes[offset_size..];
            previous_lcn = previous_lcn.saturating_add(delta);
            Some(previous_lcn)
        };
        if length == 0 {
            break;
        }
        result.push(DataRun {
            length_clusters: length,
            lcn,
        });
    }
    result
}

fn unsigned_le(bytes: &[u8]) -> u64 {
    let mut buffer = [0u8; 8];
    buffer[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(buffer)
}

fn signed_le(bytes: &[u8]) -> i64 {
    let fill = bytes.last().is_some_and(|value| value & 0x80 != 0);
    let mut buffer = [if fill { 0xFF } else { 0 }; 8];
    buffer[..bytes.len()].copy_from_slice(bytes);
    i64::from_le_bytes(buffer)
}

fn nt_time_to_unix_ms(value: u64) -> Option<i64> {
    (value != 0).then(|| {
        let ticks = value.saturating_sub(WINDOWS_EPOCH_DIFFERENCE_100NS);
        i64::try_from(ticks / 10_000).unwrap_or(i64::MAX)
    })
}

fn parse_scan_target(target: &str) -> Result<RawScanTarget, String> {
    let normalized = target.trim().replace('/', "\\");
    let bytes = normalized.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return Err("the raw helper requires an absolute drive-letter target".to_owned());
    }
    let remainder = &normalized[2..];
    if !remainder.is_empty() && !remainder.starts_with('\\') {
        return Err("the raw helper does not accept drive-relative paths".to_owned());
    }
    let components: Vec<_> = remainder
        .split('\\')
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect();
    if components
        .iter()
        .any(|component| component == "." || component == "..")
    {
        return Err("the raw helper target cannot contain relative components".to_owned());
    }
    let volume_root = format!("{}:\\", char::from(bytes[0]).to_ascii_uppercase());
    let display_path = if components.is_empty() {
        volume_root.clone()
    } else {
        format!("{volume_root}{}", components.join("\\"))
    };
    Ok(RawScanTarget {
        volume_root,
        display_path,
        components,
    })
}

fn raw_volume_path(target: &str) -> Result<String, String> {
    let trimmed = target.trim().trim_end_matches(['\\', '/']);
    let bytes = trimmed.as_bytes();
    if bytes.len() != 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return Err("the raw helper requires a drive-letter NTFS volume".to_owned());
    }
    Ok(format!(
        "\\\\.\\{}:",
        char::from(bytes[0]).to_ascii_uppercase()
    ))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_paths_are_strictly_bounded() {
        assert_eq!(raw_volume_path("c:\\"), Ok("\\\\.\\C:".to_owned()));
        assert!(raw_volume_path("C:\\Windows").is_err());
    }

    #[test]
    fn folder_targets_are_normalized_to_volume_and_components() {
        let target = parse_scan_target("c:/Users/Test/").unwrap();

        assert_eq!(target.volume_root, "C:\\");
        assert_eq!(target.display_path, "C:\\Users\\Test");
        assert_eq!(target.components, ["Users", "Test"]);
        assert!(parse_scan_target("C:relative").is_err());
        assert!(parse_scan_target("C:\\safe\\..\\escape").is_err());
    }

    #[test]
    fn data_runs_handle_sparse_and_signed_offsets() {
        let runs = decode_data_runs(&[0x11, 0x03, 0x05, 0x01, 0x02, 0x11, 0x01, 0xFF, 0]);
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].lcn, Some(5));
        assert_eq!(runs[1].lcn, None);
        assert_eq!(runs[2].lcn, Some(4));
    }

    #[test]
    fn dos_aliases_do_not_become_hard_links() {
        let mut links = SmallVec::from_vec(vec![
            LinkCandidate {
                parent_record_id: ROOT_RECORD,
                name: "Program Files".to_owned(),
                namespace: 1,
            },
            LinkCandidate {
                parent_record_id: ROOT_RECORD,
                name: "PROGRA~1".to_owned(),
                namespace: 2,
            },
        ]);
        normalize_links(&mut links);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].name, "Program Files");
    }

    #[test]
    fn resident_files_have_no_separate_cluster_allocation() {
        let mut owner = OwnerAccumulator {
            seen_base: true,
            logical_bytes: 512,
            links: SmallVec::from_vec(vec![LinkCandidate {
                parent_record_id: ROOT_RECORD,
                name: "resident.bin".to_owned(),
                namespace: 1,
            }]),
            ..OwnerAccumulator::default()
        };
        normalize_links(&mut owner.links);
        assert_eq!(owner.logical_bytes, 512);
        assert_eq!(owner.allocated_bytes, 0);
    }

    #[test]
    fn journal_positions_are_preserved_for_coverage_decisions() {
        let mut statistics = RawScanStatistics::default();
        record_journal_positions(
            &mut statistics,
            Some(JournalPosition {
                id: 11,
                next_usn: 100,
            }),
            Some(JournalPosition {
                id: 11,
                next_usn: 104,
            }),
        );

        assert_eq!(statistics.journal_id_start, Some(11));
        assert_eq!(statistics.journal_next_usn_start, Some(100));
        assert_eq!(statistics.journal_id_end, Some(11));
        assert_eq!(statistics.journal_next_usn_end, Some(104));
    }

    #[test]
    fn frozen_resident_record_covers_names_streams_attributes_and_fixups() {
        let modified_ms = 12_345i64;
        let mut fixture = FrozenMftRecord::active_file(2, 0);
        fixture.resident_attribute(0x10, &standard_information(modified_ms, 0x400), false);
        fixture.resident_attribute(
            0x30,
            &file_name_value(ROOT_RECORD, "cache.bin", 1, 4096, 128, 0),
            false,
        );
        fixture.resident_attribute(
            0x30,
            &file_name_value(ROOT_RECORD, "CACHE~1.BIN", 2, 4096, 128, 0),
            false,
        );
        fixture.resident_attribute(0x80, &[0xA5; 128], false);
        fixture.resident_attribute(0x80, &[1, 2, 3], true);
        fixture.resident_attribute(0x20, &[0; 16], false);
        let mut record = fixture.finish();

        let ParsedRecord::Valid(mut fragment) = parse_record(42, &mut record, 512) else {
            panic!("frozen resident fixture did not parse");
        };
        normalize_links(&mut fragment.links);

        assert_eq!(fragment.owner_id, 42);
        assert!(fragment.is_base);
        assert!(fragment.is_reparse_point);
        assert_eq!(fragment.modified_at_ms, Some(modified_ms));
        assert_eq!(fragment.logical_bytes, 128);
        assert_eq!(fragment.allocated_bytes, 0);
        assert_eq!(fragment.fallback_allocated_bytes, 4096);
        assert_eq!(fragment.named_streams, 1);
        assert!(fragment.has_attribute_list);
        assert_eq!(fragment.links.len(), 1);
        assert_eq!(fragment.links[0].name, "cache.bin");
    }

    #[test]
    fn frozen_nonresident_record_preserves_sparse_allocation_and_extension_owner() {
        let mut fixture = FrozenMftRecord::active_file(1, 99);
        fixture.resident_attribute(
            0x30,
            &file_name_value(ROOT_RECORD, "sparse.dat", 1, 4096, 65_536, 0),
            false,
        );
        fixture.nonresident_data_attribute(0, 4096, 65_536, false);
        fixture.nonresident_data_attribute(8, 32_768, 999_999, false);
        fixture.nonresident_data_attribute(0, 1024, 2048, true);
        let mut record = fixture.finish();

        let ParsedRecord::Valid(fragment) = parse_record(120, &mut record, 512) else {
            panic!("frozen nonresident fixture did not parse");
        };

        assert_eq!(fragment.owner_id, 99);
        assert!(!fragment.is_base);
        assert_eq!(fragment.logical_bytes, 65_536);
        assert_eq!(fragment.allocated_bytes, 4096);
        assert_eq!(fragment.named_streams, 1);
    }

    #[test]
    fn frozen_unicode_filename_and_corrupt_fixup_are_distinguished() {
        let mut fixture = FrozenMftRecord::active_file(1, 0);
        fixture.resident_attribute(
            0x30,
            &file_name_value(ROOT_RECORD, "資料.bin", 1, 512, 512, 0),
            false,
        );
        let mut valid = fixture.finish();
        let mut corrupt = valid.clone();
        corrupt[510] ^= 0xFF;

        let ParsedRecord::Valid(fragment) = parse_record(55, &mut valid, 512) else {
            panic!("unicode fixture did not parse");
        };
        assert_eq!(fragment.links[0].name, "資料.bin");
        assert!(matches!(
            parse_record(55, &mut corrupt, 512),
            ParsedRecord::Invalid
        ));
    }

    #[test]
    fn product_fixture_counts_hard_link_allocation_once() {
        let owner = OwnerAccumulator {
            seen_base: true,
            link_count: 2,
            logical_bytes: 8192,
            allocated_bytes: 4096,
            links: SmallVec::from_vec(vec![
                LinkCandidate {
                    parent_record_id: ROOT_RECORD,
                    name: "first.bin".to_owned(),
                    namespace: 1,
                },
                LinkCandidate {
                    parent_record_id: ROOT_RECORD,
                    name: "second.bin".to_owned(),
                    namespace: 1,
                },
            ]),
            ..OwnerAccumulator::default()
        };

        let product = finish_product(FinishProductInput {
            owners: vec![(30, owner)],
            target: "C:\\",
            max_records: 64,
            invalid_records: 0,
            parsed_records: 1,
            named_streams: 0,
            attribute_lists: 0,
            scope: None,
        })
        .unwrap();

        assert_eq!(product.statistics.entry_count, 2);
        assert_eq!(product.statistics.logical_bytes, 16_384);
        assert_eq!(product.statistics.allocated_bytes, 4096);
        assert_eq!(product.statistics.hard_linked_records, 1);
        assert!(product.arena.nodes[2].is_hard_link_alias());
        assert_eq!(product.arena.nodes[2].allocated_bytes, 0);
        assert_eq!(product.arena.validate(), Ok(()));
    }

    #[test]
    fn subtree_fixture_rebases_and_promotes_in_scope_hard_link() {
        let source = RawArenaSnapshot {
            nodes: vec![
                RawArenaNode {
                    name_length: 3,
                    parent: RAW_NODE_NO_INDEX,
                    first_child: 1,
                    next_sibling: RAW_NODE_NO_INDEX,
                    child_count: 2,
                    flags: RAW_NODE_FLAG_DIRECTORY,
                    ..RawArenaNode::default()
                },
                RawArenaNode {
                    name_offset: 3,
                    name_length: 6,
                    parent: 0,
                    first_child: 3,
                    next_sibling: 2,
                    child_count: 1,
                    flags: RAW_NODE_FLAG_DIRECTORY,
                    ..RawArenaNode::default()
                },
                RawArenaNode {
                    name_offset: 9,
                    name_length: 11,
                    parent: 0,
                    first_child: RAW_NODE_NO_INDEX,
                    next_sibling: RAW_NODE_NO_INDEX,
                    logical_bytes: 4096,
                    allocated_bytes: 4096,
                    hard_link_count: 2,
                    ..RawArenaNode::default()
                },
                RawArenaNode {
                    name_offset: 20,
                    name_length: 10,
                    parent: 1,
                    first_child: RAW_NODE_NO_INDEX,
                    next_sibling: RAW_NODE_NO_INDEX,
                    logical_bytes: 4096,
                    allocated_bytes: 0,
                    hard_link_count: 2,
                    flags: RAW_NODE_FLAG_HARD_LINK_ALIAS,
                    ..RawArenaNode::default()
                },
            ],
            names: b"C:\\scopedoutside.bininside.bin".to_vec(),
        };
        let target = RawScanTarget {
            volume_root: "C:\\".to_owned(),
            display_path: "C:\\scoped".to_owned(),
            components: vec!["scoped".to_owned()],
        };

        let arena = select_subtree(source, &target, &[5, 30, 42, 42], &[0, 0, 4096, 4096]).unwrap();

        assert_eq!(arena.nodes.len(), 2);
        assert_eq!(arena_name(&arena, 0), "C:\\scoped");
        assert_eq!(arena_name(&arena, 1), "inside.bin");
        assert_eq!(arena.nodes[0].allocated_bytes, 4096);
        assert_eq!(arena.nodes[1].allocated_bytes, 4096);
        assert!(!arena.nodes[1].is_hard_link_alias());
        assert_eq!(arena.validate(), Ok(()));
    }

    #[test]
    fn hierarchy_links_children_without_record_reordering() {
        let mut nodes = vec![
            test_node(true, 0),
            test_node(false, 10),
            test_node(true, 20),
        ];
        let parent_records = vec![ROOT_RECORD, 30, ROOT_RECORD];
        let mut directories = vec![RAW_NODE_NO_INDEX; 31];
        directories[ROOT_RECORD as usize] = 0;
        directories[30] = 2;

        assert_eq!(
            build_hierarchy(&mut nodes, &parent_records, &directories),
            0
        );
        assert_eq!(nodes[0].first_child, 2);
        assert!(nodes[2].is_directory());
        assert_eq!(nodes[2].name_offset, 20);
        assert_eq!(nodes[1].parent, 2);
        assert_eq!(nodes[0].allocated_bytes, 10);
    }

    #[test]
    fn hierarchy_breaks_parent_cycles_at_the_root() {
        let mut nodes = vec![test_node(true, 0), test_node(true, 1), test_node(true, 2)];
        let parent_records = vec![ROOT_RECORD, 31, 30];
        let mut directories = vec![RAW_NODE_NO_INDEX; 32];
        directories[ROOT_RECORD as usize] = 0;
        directories[30] = 1;
        directories[31] = 2;

        assert_eq!(
            build_hierarchy(&mut nodes, &parent_records, &directories),
            2
        );
        assert_eq!(nodes[1].parent, 0);
        assert_eq!(nodes[2].parent, 1);
    }

    fn test_node(is_directory: bool, name_offset: u32) -> RawArenaNode {
        RawArenaNode {
            name_offset,
            parent: RAW_NODE_NO_INDEX,
            first_child: RAW_NODE_NO_INDEX,
            next_sibling: RAW_NODE_NO_INDEX,
            logical_bytes: u64::from(!is_directory) * 10,
            allocated_bytes: u64::from(!is_directory) * 10,
            flags: if is_directory {
                RAW_NODE_FLAG_DIRECTORY
            } else {
                0
            },
            ..RawArenaNode::default()
        }
    }

    struct FrozenMftRecord {
        bytes: Vec<u8>,
        attribute_offset: usize,
    }

    impl FrozenMftRecord {
        fn active_file(link_count: u16, base_reference: u64) -> Self {
            let mut bytes = vec![0u8; 1024];
            bytes[..4].copy_from_slice(b"FILE");
            write_u16(&mut bytes, 4, 0x30);
            write_u16(&mut bytes, 6, 3);
            write_u16(&mut bytes, 18, link_count);
            write_u16(&mut bytes, 20, 0x38);
            write_u16(&mut bytes, 22, 1);
            write_u64(&mut bytes, 32, base_reference);
            bytes[0x30..0x32].copy_from_slice(&[0xA5, 0x5A]);
            bytes[0x32..0x34].copy_from_slice(&[0x11, 0x22]);
            bytes[0x34..0x36].copy_from_slice(&[0x33, 0x44]);
            bytes[510..512].copy_from_slice(&[0xA5, 0x5A]);
            bytes[1022..1024].copy_from_slice(&[0xA5, 0x5A]);
            Self {
                bytes,
                attribute_offset: 0x38,
            }
        }

        fn resident_attribute(&mut self, kind: u32, value: &[u8], named: bool) {
            let length = align_eight(24 + value.len());
            let start = self.attribute_offset;
            write_u32(&mut self.bytes, start, kind);
            write_u32(&mut self.bytes, start + 4, length as u32);
            self.bytes[start + 9] = u8::from(named);
            write_u32(&mut self.bytes, start + 16, value.len() as u32);
            write_u16(&mut self.bytes, start + 20, 24);
            self.bytes[start + 24..start + 24 + value.len()].copy_from_slice(value);
            self.attribute_offset += length;
        }

        fn nonresident_data_attribute(
            &mut self,
            lowest_vcn: u64,
            allocated_bytes: u64,
            logical_bytes: u64,
            named: bool,
        ) {
            let start = self.attribute_offset;
            write_u32(&mut self.bytes, start, 0x80);
            write_u32(&mut self.bytes, start + 4, 64);
            self.bytes[start + 8] = 1;
            self.bytes[start + 9] = u8::from(named);
            write_u64(&mut self.bytes, start + 16, lowest_vcn);
            write_u64(&mut self.bytes, start + 40, allocated_bytes);
            write_u64(&mut self.bytes, start + 48, logical_bytes);
            self.attribute_offset += 64;
        }

        fn finish(mut self) -> Vec<u8> {
            write_u32(&mut self.bytes, self.attribute_offset, u32::MAX);
            write_u32(&mut self.bytes, 24, (self.attribute_offset + 4) as u32);
            self.bytes[510..512].copy_from_slice(&[0xA5, 0x5A]);
            self.bytes[1022..1024].copy_from_slice(&[0xA5, 0x5A]);
            self.bytes
        }
    }

    fn standard_information(modified_ms: i64, attributes: u32) -> Vec<u8> {
        let mut value = vec![0u8; 72];
        let nt_time = WINDOWS_EPOCH_DIFFERENCE_100NS
            .saturating_add((modified_ms as u64).saturating_mul(10_000));
        write_u64(&mut value, 8, nt_time);
        write_u32(&mut value, 32, attributes);
        value
    }

    fn file_name_value(
        parent: u64,
        name: &str,
        namespace: u8,
        allocated_bytes: u64,
        logical_bytes: u64,
        attributes: u32,
    ) -> Vec<u8> {
        let encoded: Vec<_> = name.encode_utf16().collect();
        let mut value = vec![0u8; 66 + encoded.len() * 2];
        write_u64(&mut value, 0, parent);
        write_u64(&mut value, 40, allocated_bytes);
        write_u64(&mut value, 48, logical_bytes);
        write_u32(&mut value, 56, attributes);
        value[64] = encoded.len() as u8;
        value[65] = namespace;
        for (index, code_unit) in encoded.into_iter().enumerate() {
            value[66 + index * 2..68 + index * 2].copy_from_slice(&code_unit.to_le_bytes());
        }
        value
    }

    fn align_eight(value: usize) -> usize {
        value.saturating_add(7) & !7
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
