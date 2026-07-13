use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    analyzer::AnalyzerIndex,
    arena::{ArenaBuilder, ScanArena},
    scan::{
        ScanBackend, ScanCoverage, ScanFailure, ScanPhase, ScanProgress, ScanRequest, ScanSummary,
        ScanTargetKind, ScanWarning,
    },
    traversal::{FileIdentity, TraversalEvent, traverse},
};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct ScanOutput {
    pub arena: ScanArena,
    pub analyzer: AnalyzerIndex,
    pub summary: ScanSummary,
}

pub trait ScanBackendEngine {
    fn kind(&self) -> ScanBackend;

    fn scan(
        &self,
        request: ScanRequest,
        session_id: String,
        cancel: Arc<AtomicBool>,
        on_progress: &mut dyn FnMut(ScanProgress),
    ) -> Result<ScanOutput, ScanFailure>;
}

pub struct TraversalBackend;

impl ScanBackendEngine for TraversalBackend {
    fn kind(&self) -> ScanBackend {
        ScanBackend::Traversal
    }

    fn scan(
        &self,
        request: ScanRequest,
        session_id: String,
        cancel: Arc<AtomicBool>,
        on_progress: &mut dyn FnMut(ScanProgress),
    ) -> Result<ScanOutput, ScanFailure> {
        let started = Instant::now();
        let root = PathBuf::from(&request.target.display_path);
        let mut builder = ArenaBuilder::new(root.clone())?;
        let mut hard_links = HashSet::new();
        let mut warning_ledger = WarningLedger::default();
        let mut entries_seen = 0u64;
        let mut bytes_accounted = 0u64;
        let mut last_progress = Instant::now();

        warning_ledger.record(ScanWarning {
            code: "TRAVERSAL_BACKEND".to_owned(),
            detail:
                "Read-only filesystem traversal is active; the elevated MFT helper is not in use"
                    .to_owned(),
        });
        on_progress(progress(
            &session_id,
            ScanPhase::Preparing,
            self.kind(),
            entries_seen,
            bytes_accounted,
            started.elapsed(),
            Vec::new(),
        ));

        let report = traverse(&root, Arc::clone(&cancel), |batch| {
            let mut recent_warnings = Vec::new();
            for event in batch {
                match event {
                    TraversalEvent::Entry {
                        mut entry,
                        identity,
                    } => {
                        normalize_hard_link(&mut entry, identity, &mut hard_links);
                        entries_seen = entries_seen.saturating_add(1);
                        bytes_accounted = bytes_accounted.saturating_add(entry.allocated_bytes);
                        builder.push(entry)?;
                    }
                    TraversalEvent::Inaccessible {
                        temporary_id,
                        path: _,
                    } => builder.mark_inaccessible(temporary_id)?,
                    TraversalEvent::Warning(warning) => {
                        if recent_warnings.len() < 3 {
                            recent_warnings.push(warning.clone());
                        }
                        warning_ledger.record(warning);
                    }
                }
            }

            if last_progress.elapsed() >= Duration::from_millis(100) {
                on_progress(progress(
                    &session_id,
                    ScanPhase::Enumerating,
                    self.kind(),
                    entries_seen,
                    bytes_accounted,
                    started.elapsed(),
                    recent_warnings,
                ));
                last_progress = Instant::now();
            }
            Ok(())
        })?;

        on_progress(progress(
            &session_id,
            ScanPhase::Indexing,
            self.kind(),
            entries_seen,
            bytes_accounted,
            started.elapsed(),
            Vec::new(),
        ));
        let arena = builder.finish(session_id.clone());
        let volume_used_bytes = used_bytes(&request);
        let unaccounted_bytes = volume_used_bytes
            .and_then(|used| used.checked_sub(arena.allocated_bytes()))
            .map(|value| value.to_string());
        let coverage = if report.inaccessible_paths > 0 {
            ScanCoverage::Partial
        } else {
            ScanCoverage::Complete
        };
        let warnings = warning_ledger.finish();
        let mut summary = ScanSummary {
            session_id: session_id.clone(),
            target: request.target,
            backend: self.kind(),
            coverage,
            entry_count: arena.entry_count().to_string(),
            logical_bytes: arena.logical_bytes().to_string(),
            allocated_bytes: arena.allocated_bytes().to_string(),
            volume_used_bytes: volume_used_bytes.map(|value| value.to_string()),
            unaccounted_bytes,
            elapsed_ms: elapsed_ms(started.elapsed()).to_string(),
            warnings,
        };

        on_progress(progress(
            &session_id,
            ScanPhase::Classifying,
            self.kind(),
            entries_seen,
            arena.allocated_bytes(),
            started.elapsed(),
            Vec::new(),
        ));
        let analyzer = AnalyzerIndex::build(&arena, coverage);
        summary.elapsed_ms = elapsed_ms(started.elapsed()).to_string();
        on_progress(progress(
            &session_id,
            ScanPhase::Finalizing,
            self.kind(),
            entries_seen,
            arena.allocated_bytes(),
            started.elapsed(),
            Vec::new(),
        ));
        Ok(ScanOutput {
            arena,
            analyzer,
            summary,
        })
    }
}

pub struct RawNtfsBackend;

impl ScanBackendEngine for RawNtfsBackend {
    fn kind(&self) -> ScanBackend {
        ScanBackend::RawNtfs
    }

    fn scan(
        &self,
        request: ScanRequest,
        session_id: String,
        cancel: Arc<AtomicBool>,
        on_progress: &mut dyn FnMut(ScanProgress),
    ) -> Result<ScanOutput, ScanFailure> {
        #[cfg(windows)]
        {
            let started = Instant::now();
            on_progress(progress(
                &session_id,
                ScanPhase::Elevating,
                self.kind(),
                0,
                0,
                started.elapsed(),
                Vec::new(),
            ));
            let mut helper_progress = |phase, records_seen, _mft_bytes_read, elapsed_ms| {
                let phase = match phase {
                    clutter_protocol::RawScanPhase::Preparing => ScanPhase::Preparing,
                    clutter_protocol::RawScanPhase::Enumerating => ScanPhase::Enumerating,
                    clutter_protocol::RawScanPhase::Indexing => ScanPhase::Indexing,
                    clutter_protocol::RawScanPhase::Finalizing => ScanPhase::Finalizing,
                };
                on_progress(progress(
                    &session_id,
                    phase,
                    self.kind(),
                    records_seen,
                    0,
                    Duration::from_millis(elapsed_ms),
                    Vec::new(),
                ));
            };
            let mut product = crate::raw_snapshot::scan_with_helper(
                &request.target.display_path,
                PathBuf::from(&request.target.display_path),
                session_id.clone(),
                cancel,
                &mut helper_progress,
            )?;
            on_progress(progress(
                &session_id,
                ScanPhase::Indexing,
                self.kind(),
                product.statistics.entry_count,
                product.arena.allocated_bytes(),
                started.elapsed(),
                product.warnings.iter().take(3).cloned().collect(),
            ));
            let volume_used_bytes = used_bytes(&request);
            let unaccounted_bytes = volume_used_bytes
                .and_then(|used| used.checked_sub(product.arena.allocated_bytes()))
                .map(|value| value.to_string());
            let journal_changed = raw_journal_changed(&product.statistics);
            if journal_changed {
                product.warnings.push(ScanWarning {
                    code: "USN_JOURNAL_CHANGED".to_owned(),
                    detail:
                        "The NTFS change journal advanced during the scan; rescan before cleanup"
                            .to_owned(),
                });
            }
            let coverage = if journal_changed {
                ScanCoverage::PotentiallyStale
            } else if product.warnings.iter().any(|warning| {
                matches!(
                    warning.code.as_str(),
                    "INVALID_MFT_RECORDS" | "ORPHAN_MFT_EXTENTS" | "ORPHAN_MFT_PARENT"
                )
            }) {
                ScanCoverage::Partial
            } else {
                ScanCoverage::Complete
            };
            let mut summary = ScanSummary {
                session_id: session_id.clone(),
                target: request.target,
                backend: self.kind(),
                coverage,
                entry_count: product.arena.entry_count().to_string(),
                logical_bytes: product.arena.logical_bytes().to_string(),
                allocated_bytes: product.arena.allocated_bytes().to_string(),
                volume_used_bytes: volume_used_bytes.map(|value| value.to_string()),
                unaccounted_bytes,
                elapsed_ms: elapsed_ms(started.elapsed()).to_string(),
                warnings: product.warnings,
            };
            on_progress(progress(
                &session_id,
                ScanPhase::Classifying,
                self.kind(),
                product.statistics.entry_count,
                product.arena.allocated_bytes(),
                started.elapsed(),
                Vec::new(),
            ));
            let analyzer = AnalyzerIndex::build(&product.arena, coverage);
            summary.elapsed_ms = elapsed_ms(started.elapsed()).to_string();
            on_progress(progress(
                &session_id,
                ScanPhase::Finalizing,
                self.kind(),
                product.statistics.entry_count,
                product.arena.allocated_bytes(),
                started.elapsed(),
                Vec::new(),
            ));
            Ok(ScanOutput {
                arena: product.arena,
                analyzer,
                summary,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (request, session_id, cancel, on_progress);
            Err(ScanFailure::new(
                "RAW_NTFS_HELPER_REQUIRED",
                "Fast NTFS scanning requires the elevated Windows helper",
                true,
            ))
        }
    }
}

pub fn run_scan(
    request: ScanRequest,
    session_id: String,
    cancel: Arc<AtomicBool>,
    mut on_progress: impl FnMut(ScanProgress),
) -> Result<ScanOutput, ScanFailure> {
    validate_scan_request(&request)?;
    match request.preferred_backend {
        ScanBackend::RawNtfs => RawNtfsBackend.scan(request, session_id, cancel, &mut on_progress),
        ScanBackend::Traversal => {
            TraversalBackend.scan(request, session_id, cancel, &mut on_progress)
        }
    }
}

fn validate_scan_request(request: &ScanRequest) -> Result<(), ScanFailure> {
    let is_ntfs = request
        .target
        .filesystem
        .as_deref()
        .is_some_and(|filesystem| filesystem.eq_ignore_ascii_case("NTFS"));
    if request.target.kind == ScanTargetKind::Volume && !is_ntfs {
        return Err(ScanFailure::new(
            "UNSUPPORTED_FILESYSTEM",
            "Whole-volume scans require NTFS; select a folder to use traversal instead",
            true,
        ));
    }
    if request.preferred_backend == ScanBackend::RawNtfs
        && (!is_ntfs || !request.target.fast_scan_available)
    {
        return Err(ScanFailure::new(
            "RAW_NTFS_UNAVAILABLE",
            "Fast scanning requires an eligible NTFS volume or folder",
            true,
        ));
    }
    Ok(())
}

pub fn new_session_id() -> String {
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("scan-{epoch_ms:x}-{counter:x}")
}

fn normalize_hard_link(
    entry: &mut crate::arena::DiscoveredEntry,
    identity: Option<FileIdentity>,
    seen: &mut HashSet<(u64, u64)>,
) {
    let Some(identity) = identity.filter(|identity| identity.links > 1) else {
        return;
    };
    if entry.is_directory || entry.is_reparse_point {
        return;
    }
    if !seen.insert((identity.volume, identity.file)) {
        entry.allocated_bytes = 0;
        entry.hard_link_alias = true;
    }
}

fn used_bytes(request: &ScanRequest) -> Option<u64> {
    let total = request.target.total_bytes.as_deref()?.parse::<u64>().ok()?;
    let available = request
        .target
        .available_bytes
        .as_deref()?
        .parse::<u64>()
        .ok()?;
    total.checked_sub(available)
}

fn progress(
    session_id: &str,
    phase: ScanPhase,
    backend: ScanBackend,
    entries_seen: u64,
    bytes_accounted: u64,
    elapsed: Duration,
    warnings: Vec<ScanWarning>,
) -> ScanProgress {
    ScanProgress {
        session_id: session_id.to_owned(),
        phase,
        backend,
        entries_seen: entries_seen.to_string(),
        bytes_accounted: bytes_accounted.to_string(),
        elapsed_ms: elapsed_ms(elapsed).to_string(),
        warnings,
    }
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(windows)]
fn raw_journal_changed(statistics: &clutter_protocol::RawScanStatistics) -> bool {
    match (
        statistics.journal_id_start,
        statistics.journal_next_usn_start,
        statistics.journal_id_end,
        statistics.journal_next_usn_end,
    ) {
        (Some(start_id), Some(start_usn), Some(end_id), Some(end_usn)) => {
            start_id != end_id || start_usn != end_usn
        }
        _ => false,
    }
}

#[derive(Default)]
struct WarningLedger {
    entries: HashMap<String, (u64, String)>,
}

impl WarningLedger {
    fn record(&mut self, warning: ScanWarning) {
        let entry = self
            .entries
            .entry(warning.code)
            .or_insert((0, warning.detail));
        entry.0 = entry.0.saturating_add(1);
    }

    fn finish(self) -> Vec<ScanWarning> {
        let mut warnings: Vec<_> = self
            .entries
            .into_iter()
            .map(|(code, (count, detail))| ScanWarning {
                code,
                detail: if count > 1 {
                    format!("{detail} (+{} similar)", count - 1)
                } else {
                    detail
                },
            })
            .collect();
        warnings.sort_by(|left, right| left.code.cmp(&right.code));
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arena::DiscoveredEntry,
        scan::{ScanTarget, ScanTargetKind},
    };

    #[test]
    fn hard_link_aliases_contribute_no_second_allocation() {
        let identity = FileIdentity {
            volume: 1,
            file: 2,
            links: 2,
        };
        let mut seen = HashSet::new();
        let mut first = file_entry(4096);
        let mut second = file_entry(4096);

        normalize_hard_link(&mut first, Some(identity), &mut seen);
        normalize_hard_link(&mut second, Some(identity), &mut seen);

        assert_eq!(first.allocated_bytes, 4096);
        assert_eq!(second.allocated_bytes, 0);
        assert!(second.hard_link_alias);
    }

    #[test]
    fn used_space_uses_decimal_string_contract() {
        let request = ScanRequest {
            target: ScanTarget {
                id: "test".to_owned(),
                kind: ScanTargetKind::Volume,
                display_path: "C:\\".to_owned(),
                filesystem: Some("NTFS".to_owned()),
                volume_id: None,
                total_bytes: Some("100".to_owned()),
                available_bytes: Some("40".to_owned()),
                fast_scan_available: true,
            },
            preferred_backend: ScanBackend::Traversal,
        };

        assert_eq!(used_bytes(&request), Some(60));
    }

    #[test]
    fn non_ntfs_volumes_are_rejected_but_folders_can_traverse() {
        let mut request = ScanRequest {
            target: ScanTarget {
                id: "test".to_owned(),
                kind: ScanTargetKind::Volume,
                display_path: "E:\\".to_owned(),
                filesystem: Some("exFAT".to_owned()),
                volume_id: None,
                total_bytes: None,
                available_bytes: None,
                fast_scan_available: false,
            },
            preferred_backend: ScanBackend::Traversal,
        };

        assert_eq!(
            validate_scan_request(&request).unwrap_err().code,
            "UNSUPPORTED_FILESYSTEM"
        );
        request.target.kind = ScanTargetKind::Folder;
        assert_eq!(validate_scan_request(&request), Ok(()));
        request.preferred_backend = ScanBackend::RawNtfs;
        assert_eq!(
            validate_scan_request(&request).unwrap_err().code,
            "RAW_NTFS_UNAVAILABLE"
        );
    }

    #[cfg(windows)]
    #[test]
    fn journal_change_requires_stale_coverage() {
        let unchanged = clutter_protocol::RawScanStatistics {
            journal_id_start: Some(7),
            journal_next_usn_start: Some(100),
            journal_id_end: Some(7),
            journal_next_usn_end: Some(100),
            ..clutter_protocol::RawScanStatistics::default()
        };
        assert!(!raw_journal_changed(&unchanged));

        let advanced = clutter_protocol::RawScanStatistics {
            journal_next_usn_end: Some(101),
            ..unchanged
        };
        assert!(raw_journal_changed(&advanced));
    }

    fn file_entry(allocated_bytes: u64) -> DiscoveredEntry {
        DiscoveredEntry {
            temporary_id: 1,
            parent_temporary_id: Some(0),
            name: "file.bin".to_owned(),
            is_directory: false,
            is_reparse_point: false,
            inaccessible: false,
            logical_bytes: allocated_bytes,
            allocated_bytes,
            modified_at_ms: None,
            hard_link_count: Some(2),
            hard_link_alias: false,
        }
    }
}
