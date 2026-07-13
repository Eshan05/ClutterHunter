use clutter_protocol::PROTOCOL_VERSION;

#[cfg(windows)]
mod raw_mft;

#[cfg(windows)]
fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, target] if command == "probe" => run_probe(target),
        [command, target, output, cancel, nonce] if command == "snapshot" => {
            run_snapshot(target, output, cancel, nonce)
        }
        [command, target, pipe, nonce] if command == "stream" => run_stream(target, pipe, nonce),
        [command, snapshot, nonce] if command == "inspect" => run_inspect(snapshot, nonce),
        _ => {
            eprintln!("Usage:");
            eprintln!("  clutter-scanner-helper probe <volume>");
            eprintln!("  clutter-scanner-helper snapshot <volume> <output> <cancel> <nonce>");
            eprintln!("  clutter-scanner-helper stream <volume> <pipe> <nonce>");
            eprintln!("  clutter-scanner-helper inspect <snapshot> <nonce>");
            std::process::exit(64);
        }
    }
}

#[cfg(windows)]
fn run_stream(target: &str, pipe: &str, nonce: &str) {
    use std::{
        fs::OpenOptions,
        io::BufWriter,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use clutter_protocol::{
        HelperHello, HelperMessage, RAW_NAME_BATCH_SIZE, RAW_NODE_BATCH_SIZE, RawArenaSnapshot,
    };

    let nonce = match decode_nonce(nonce) {
        Some(value) => value,
        None => {
            eprintln!("Stream nonce must contain exactly 64 hexadecimal characters");
            std::process::exit(64);
        }
    };
    let expected_pipe = format!(
        "\\\\.\\pipe\\ClutterHunter-{nonce}",
        nonce = encode_nonce(&nonce)
    );
    if !pipe.eq_ignore_ascii_case(&expected_pipe) {
        eprintln!("Stream pipe does not match the scan nonce");
        std::process::exit(64);
    }
    let file = (0..100)
        .find_map(
            |_| match OpenOptions::new().read(true).write(true).open(pipe) {
                Ok(file) => Some(file),
                Err(_) => {
                    thread::sleep(Duration::from_millis(50));
                    None
                }
            },
        )
        .unwrap_or_else(|| {
            eprintln!("Could not connect to the scanner stream pipe");
            std::process::exit(1);
        });
    let mut cancel_reader = file.try_clone().unwrap_or_else(|error| {
        eprintln!("Could not open the scanner cancellation stream: {error}");
        std::process::exit(1);
    });
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancellation_flag = Arc::clone(&cancelled);
    thread::spawn(move || {
        if matches!(receive_frame(&mut cancel_reader), Ok(HelperMessage::Cancel)) {
            cancellation_flag.store(true, Ordering::Release);
        }
    });
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    if let Err(error) = send_frame(
        &mut writer,
        &HelperMessage::Hello(HelperHello {
            protocol_version: PROTOCOL_VERSION,
            nonce,
            helper_pid: std::process::id(),
            target: target.to_owned(),
        }),
    ) {
        eprintln!("Could not start scanner stream: {error}");
        std::process::exit(1);
    }

    let scan = raw_mft::scan(
        target,
        || cancelled.load(Ordering::Acquire),
        |phase, records, bytes, elapsed| {
            send_frame(
                &mut writer,
                &HelperMessage::Progress {
                    phase,
                    records_seen: records,
                    mft_bytes_read: bytes,
                    elapsed_ms: elapsed,
                },
            )
        },
    );
    let result = scan.and_then(|product| {
        let stream_started = Instant::now();
        let raw_mft::ScanProduct {
            arena,
            mut statistics,
            warnings,
        } = product;
        let RawArenaSnapshot { nodes, names } = arena;
        let node_count = u32::try_from(nodes.len())
            .map_err(|_| "the raw arena exceeded its stream node limit".to_owned())?;
        let name_bytes = u32::try_from(names.len())
            .map_err(|_| "the raw arena exceeded its stream name limit".to_owned())?;
        send_frame(
            &mut writer,
            &HelperMessage::ArenaHeader {
                node_count,
                name_bytes,
            },
        )?;
        for warning in warnings {
            send_frame(
                &mut writer,
                &HelperMessage::Warning {
                    code: warning.code,
                    detail: warning.detail,
                },
            )?;
        }
        for (sequence, batch) in nodes.chunks(RAW_NODE_BATCH_SIZE).enumerate() {
            send_frame(
                &mut writer,
                &HelperMessage::NodeBatch {
                    sequence: sequence as u32,
                    nodes: batch.to_vec(),
                },
            )?;
        }
        for (sequence, batch) in names.chunks(RAW_NAME_BATCH_SIZE).enumerate() {
            send_frame(
                &mut writer,
                &HelperMessage::NameBatch {
                    sequence: sequence as u32,
                    bytes: batch.to_vec(),
                },
            )?;
        }
        statistics.stream_ms =
            u64::try_from(stream_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        statistics.helper_peak_working_set_bytes = process_peak_working_set_bytes().unwrap_or(0);
        send_frame(&mut writer, &HelperMessage::Complete { statistics })
    });
    if let Err(detail) = result {
        let code = if detail == "scan cancelled" {
            "SCAN_CANCELLED"
        } else {
            "RAW_NTFS_SCAN_FAILED"
        };
        let _ = send_frame(
            &mut writer,
            &HelperMessage::Error {
                code: code.to_owned(),
                recoverable: true,
                detail: detail.clone(),
            },
        );
        eprintln!("{code}: {detail}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn process_peak_working_set_bytes() -> Option<u64> {
    use windows::Win32::System::{
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::GetCurrentProcess,
    };

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

#[cfg(windows)]
fn send_frame(
    writer: &mut impl std::io::Write,
    message: &clutter_protocol::HelperMessage,
) -> Result<(), String> {
    use clutter_protocol::RAW_FRAME_LIMIT;

    let bytes = bincode::serde::encode_to_vec(message, bincode::config::standard())
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > RAW_FRAME_LIMIT {
        return Err("a scanner stream frame exceeded its bounded size".to_owned());
    }
    let length = u32::try_from(bytes.len()).map_err(|error| error.to_string())?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .and_then(|_| writer.flush())
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn receive_frame(
    reader: &mut impl std::io::Read,
) -> Result<clutter_protocol::HelperMessage, String> {
    use clutter_protocol::RAW_FRAME_LIMIT;

    let mut length = [0u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| error.to_string())?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > RAW_FRAME_LIMIT {
        return Err("a scanner stream frame exceeded its bounded size".to_owned());
    }
    let mut bytes = vec![0u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    let (message, consumed) = bincode::serde::decode_from_slice(
        &bytes,
        bincode::config::standard().with_limit::<RAW_FRAME_LIMIT>(),
    )
    .map_err(|error| error.to_string())?;
    if consumed != bytes.len() {
        return Err("a scanner stream frame had trailing data".to_owned());
    }
    Ok(message)
}

#[cfg(windows)]
fn run_inspect(snapshot: &str, nonce: &str) {
    use std::{fs::File, io::BufReader};

    use clutter_protocol::{RawScanEnvelope, RawScanOutcome};

    let Some(expected_nonce) = decode_nonce(nonce) else {
        eprintln!("Snapshot nonce must contain exactly 64 hexadecimal characters");
        std::process::exit(64);
    };
    let mut reader = match File::open(snapshot).map(BufReader::new) {
        Ok(reader) => reader,
        Err(error) => {
            eprintln!("Could not open raw scan snapshot: {error}");
            std::process::exit(1);
        }
    };
    let envelope: RawScanEnvelope = match bincode::serde::decode_from_std_read(
        &mut reader,
        bincode::config::standard().with_limit::<{ 4 * 1024 * 1024 * 1024 }>(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            eprintln!("Could not decode raw scan snapshot: {error}");
            std::process::exit(1);
        }
    };
    if envelope.protocol_version != PROTOCOL_VERSION || envelope.nonce != expected_nonce {
        eprintln!("Snapshot identity does not match the requested scan");
        std::process::exit(1);
    }
    println!("protocol_version={}", envelope.protocol_version);
    println!("helper_pid={}", envelope.helper_pid);
    println!("target={}", envelope.target);
    match envelope.outcome {
        RawScanOutcome::Complete {
            arena,
            statistics,
            warnings,
        } => {
            if let Err(error) = arena.validate() {
                eprintln!("Snapshot arena failed validation: {error}");
                std::process::exit(1);
            }
            println!("mft_record_count={}", statistics.mft_record_count);
            println!("mft_bytes_read={}", statistics.mft_bytes_read);
            println!("mft_data_runs={}", statistics.mft_data_runs);
            println!("ingest_ms={}", statistics.ingest_ms);
            println!("finalize_ms={}", statistics.finalize_ms);
            println!("elapsed_ms={}", statistics.elapsed_ms);
            println!("entry_count={}", statistics.entry_count);
            println!("file_count={}", statistics.file_count);
            println!("directory_count={}", statistics.directory_count);
            println!("logical_bytes={}", statistics.logical_bytes);
            println!("allocated_bytes={}", statistics.allocated_bytes);
            println!("hard_linked_records={}", statistics.hard_linked_records);
            println!("reparse_points={}", statistics.reparse_points);
            println!("named_data_streams={}", statistics.named_data_streams);
            println!(
                "attribute_list_records={}",
                statistics.attribute_list_records
            );
            println!("decoded_entries={}", arena.nodes.len().saturating_sub(1));
            println!("decoded_name_bytes={}", arena.names.len());
            for warning in warnings {
                println!("warning={} {}", warning.code, warning.detail);
            }
        }
        RawScanOutcome::Error { code, detail, .. } => {
            eprintln!("{code}: {detail}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn run_probe(target: &str) {
    match raw_ntfs::scan_statistics(target) {
        Ok(statistics) => {
            println!("ClutterHunter scanner helper protocol v{PROTOCOL_VERSION}");
            println!("{statistics:#?}");
        }
        Err(error) => {
            eprintln!("Raw NTFS probe failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn run_snapshot(target: &str, output: &str, cancel: &str, nonce: &str) {
    use std::{
        fs::OpenOptions,
        io::{BufWriter, Write as _},
        path::Path,
    };

    use clutter_protocol::{RawScanEnvelope, RawScanOutcome};

    let nonce = match decode_nonce(nonce) {
        Some(value) => value,
        None => {
            eprintln!("Snapshot nonce must contain exactly 64 hexadecimal characters");
            std::process::exit(64);
        }
    };
    let outcome = match raw_mft::scan(target, || Path::new(cancel).exists(), |_, _, _, _| Ok(())) {
        Ok(product) => RawScanOutcome::Complete {
            arena: product.arena,
            statistics: Box::new(product.statistics),
            warnings: product.warnings,
        },
        Err(detail) => RawScanOutcome::Error {
            code: if detail == "scan cancelled" {
                "SCAN_CANCELLED".to_owned()
            } else {
                "RAW_NTFS_SCAN_FAILED".to_owned()
            },
            recoverable: true,
            detail,
        },
    };
    let envelope = RawScanEnvelope {
        protocol_version: PROTOCOL_VERSION,
        nonce,
        helper_pid: std::process::id(),
        target: target.to_owned(),
        outcome,
    };
    let file = match OpenOptions::new().write(true).create_new(true).open(output) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Could not create raw scan snapshot: {error}");
            std::process::exit(1);
        }
    };
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    if let Err(error) =
        bincode::serde::encode_into_std_write(&envelope, &mut writer, bincode::config::standard())
    {
        eprintln!("Could not write raw scan snapshot: {error}");
        std::process::exit(1);
    }
    if let Err(error) = writer.flush() {
        eprintln!("Could not flush raw scan snapshot: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn decode_nonce(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut nonce = [0u8; 32];
    for (index, byte) in nonce.iter_mut().enumerate() {
        *byte = u8::from_str_radix(value.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(nonce)
}

#[cfg(windows)]
fn encode_nonce(nonce: &[u8; 32]) -> String {
    let mut result = String::with_capacity(64);
    for byte in nonce {
        use std::fmt::Write as _;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ClutterHunter raw NTFS helper is only available on Windows");
    std::process::exit(64);
}

#[cfg(all(test, windows))]
mod transport_tests {
    use clutter_protocol::{
        PROTOCOL_VERSION, RAW_NODE_FLAG_DIRECTORY, RAW_NODE_NO_INDEX, RawArenaNode,
        RawArenaSnapshot, RawScanEnvelope, RawScanOutcome, RawScanStatistics,
    };

    #[test]
    fn snapshot_envelope_round_trips_through_bincode() {
        let envelope = RawScanEnvelope {
            protocol_version: PROTOCOL_VERSION,
            nonce: [7; 32],
            helper_pid: 42,
            target: "C:\\".to_owned(),
            outcome: RawScanOutcome::Complete {
                arena: RawArenaSnapshot {
                    nodes: vec![RawArenaNode {
                        parent: RAW_NODE_NO_INDEX,
                        flags: RAW_NODE_FLAG_DIRECTORY,
                        ..RawArenaNode::default()
                    }],
                    names: b"C:\\".to_vec(),
                },
                statistics: Box::new(RawScanStatistics::default()),
                warnings: Vec::new(),
            },
        };

        let bytes = bincode::serde::encode_to_vec(&envelope, bincode::config::standard()).unwrap();
        let (decoded, consumed): (RawScanEnvelope, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();

        assert_eq!(decoded, envelope);
        assert_eq!(consumed, bytes.len());
    }
}

#[cfg(windows)]
mod raw_ntfs {
    use clutter_protocol::RawScanStatistics;
    use ntfs_reader::{
        api::{NtfsAttributeType, NtfsFileNameFlags},
        mft::Mft,
        volume::Volume,
    };

    pub fn scan_statistics(target: &str) -> Result<RawScanStatistics, Box<dyn std::error::Error>> {
        let raw_path = raw_volume_path(target)?;
        let volume = Volume::new(raw_path)?;
        let mft = Mft::new(volume)?;
        let mut statistics = RawScanStatistics::default();

        for file in mft.files() {
            if packed_u64(std::ptr::addr_of!(file.header.base_reference)) != 0 {
                continue;
            }
            statistics.entry_count = statistics.entry_count.saturating_add(1);
            if file.is_directory() {
                statistics.directory_count = statistics.directory_count.saturating_add(1);
            } else {
                statistics.file_count = statistics.file_count.saturating_add(1);
            }

            let link_count = packed_u16(std::ptr::addr_of!(file.header.link_count));
            if link_count > 1 {
                statistics.hard_linked_records = statistics.hard_linked_records.saturating_add(1);
            }

            file.attributes(|attribute| {
                let type_id = packed_u32(std::ptr::addr_of!(attribute.header.type_id));
                if type_id == NtfsAttributeType::AttributeList as u32 {
                    statistics.attribute_list_records =
                        statistics.attribute_list_records.saturating_add(1);
                }
                if type_id == NtfsAttributeType::StandardInformation as u32
                    && let Some(information) = attribute.as_standard_info()
                {
                    let attributes = packed_u32(std::ptr::addr_of!(information.file_attributes));
                    if attributes & NtfsFileNameFlags::ReparsePoint as u32 != 0 {
                        statistics.reparse_points = statistics.reparse_points.saturating_add(1);
                    }
                }
                if type_id != NtfsAttributeType::Data as u32 {
                    return;
                }

                let name_length = packed_u8(std::ptr::addr_of!(attribute.header.name_length));
                if name_length > 0 {
                    statistics.named_data_streams = statistics.named_data_streams.saturating_add(1);
                }
                if let Some(header) = attribute.nonresident_header() {
                    statistics.logical_bytes = statistics
                        .logical_bytes
                        .saturating_add(packed_u64(std::ptr::addr_of!(header.data_size)));
                    statistics.allocated_bytes = statistics
                        .allocated_bytes
                        .saturating_add(packed_u64(std::ptr::addr_of!(header.allocated_size)));
                } else if let Some(header) = attribute.resident_header() {
                    statistics.logical_bytes =
                        statistics
                            .logical_bytes
                            .saturating_add(u64::from(packed_u32(std::ptr::addr_of!(
                                header.value_length
                            ))));
                }
            });
        }

        Ok(statistics)
    }

    fn raw_volume_path(target: &str) -> Result<String, &'static str> {
        let trimmed = target.trim().trim_end_matches(['\\', '/']);
        let bytes = trimmed.as_bytes();
        if bytes.len() != 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
            return Err("the raw helper currently requires a drive-letter volume");
        }
        Ok(format!(
            "\\\\.\\{}:",
            char::from(bytes[0]).to_ascii_uppercase()
        ))
    }

    fn packed_u8(pointer: *const u8) -> u8 {
        unsafe { pointer.read_unaligned() }
    }

    fn packed_u16(pointer: *const u16) -> u16 {
        unsafe { pointer.read_unaligned() }
    }

    fn packed_u32(pointer: *const u32) -> u32 {
        unsafe { pointer.read_unaligned() }
    }

    fn packed_u64(pointer: *const u64) -> u64 {
        unsafe { pointer.read_unaligned() }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn volume_paths_are_strictly_bounded() {
            assert_eq!(raw_volume_path("c:\\"), Ok("\\\\.\\C:".to_owned()));
            assert!(raw_volume_path("C:\\Windows").is_err());
        }
    }
}
