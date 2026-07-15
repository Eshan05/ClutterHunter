use std::{
    collections::HashMap,
    io::{Read as _, Seek as _, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use clutter_core::{
    analyzer::AnalyzerSettings,
    backend::{ScanOutput, new_session_id, run_scan},
    scan::{
        CleanupPlan, CleanupPlanRequest, DismissSuggestionRequest, HardwareProfile, ItemDetails,
        ItemPage, ItemQuery, LogExcerpt, LogExcerptBatch, LogExcerptRequest, PathProtectionRequest,
        PlanEdit, PolicyEvidence, PolicyTier, ScanFailure, ScanProgress, ScanRequest, ScanSummary,
        ScanTarget, StorageAggregate, StorageAggregateQuery, TreemapQuery, TreemapSlice,
        default_scan_targets,
    },
};
use tauri::{State, ipc::Channel};

const MAX_ANALYZER_SETTINGS_BYTES: usize = 1024 * 1024;
const MAX_LOG_EXCERPT_FILES: usize = 5;
const MAX_LOG_EXCERPT_BYTES_PER_FILE: usize = 64 * 1024;
const MAX_LOG_EXCERPT_TOTAL_BYTES: usize = 256 * 1024;
static SETTINGS_WRITE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct ScannerState {
    active: Mutex<Option<ActiveScan>>,
    completed: Mutex<Option<Arc<RwLock<ScanOutput>>>>,
    queries: Mutex<HashMap<(String, String), Arc<AtomicBool>>>,
    plan: Mutex<Option<CleanupPlan>>,
    settings: Mutex<AnalyzerSettings>,
}

impl Default for ScannerState {
    fn default() -> Self {
        Self {
            active: Mutex::new(None),
            completed: Mutex::new(None),
            queries: Mutex::new(HashMap::new()),
            plan: Mutex::new(None),
            settings: Mutex::new(load_analyzer_settings()),
        }
    }
}

struct ActiveScan {
    session_id: String,
    cancel: Arc<AtomicBool>,
}

#[tauri::command]
pub fn list_scan_targets() -> Vec<ScanTarget> {
    default_scan_targets()
}

#[tauri::command]
pub fn get_hardware_profile() -> Result<HardwareProfile, ScanFailure> {
    hardware_profile()
}

#[cfg(windows)]
fn hardware_profile() -> Result<HardwareProfile, ScanFailure> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe { GlobalMemoryStatusEx(&mut status) }.map_err(|error| {
        ScanFailure::new(
            "HARDWARE_PROFILE_UNAVAILABLE",
            format!("Windows memory information was unavailable: {error}"),
            true,
        )
    })?;
    Ok(HardwareProfile {
        total_memory_bytes: status.ullTotalPhys.to_string(),
        available_memory_bytes: status.ullAvailPhys.to_string(),
    })
}

#[cfg(not(windows))]
fn hardware_profile() -> Result<HardwareProfile, ScanFailure> {
    Err(ScanFailure::new(
        "HARDWARE_PROFILE_UNAVAILABLE",
        "The first release supports Windows hardware discovery only",
        true,
    ))
}

#[tauri::command]
pub async fn start_scan(
    request: ScanRequest,
    on_progress: Channel<ScanProgress>,
    state: State<'_, ScannerState>,
) -> Result<ScanSummary, ScanFailure> {
    cancel_active_queries(&state)?;
    let session_id = new_session_id();
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state.active.lock().map_err(|_| internal_state_failure())?;
        if active.is_some() {
            return Err(ScanFailure::new(
                "SCAN_ALREADY_RUNNING",
                "Only one scan can run at a time",
                true,
            ));
        }
        *active = Some(ActiveScan {
            session_id: session_id.clone(),
            cancel: Arc::clone(&cancel),
        });
    }

    let worker_session_id = session_id.clone();
    let worker_result = tauri::async_runtime::spawn_blocking(move || {
        run_scan(request, worker_session_id, cancel, |progress| {
            let _ = on_progress.send(progress);
        })
    })
    .await;

    {
        let mut active = state.active.lock().map_err(|_| internal_state_failure())?;
        if active
            .as_ref()
            .is_some_and(|scan| scan.session_id == session_id)
        {
            *active = None;
        }
    }

    let mut output = worker_result.map_err(|error| {
        ScanFailure::new(
            "SCAN_WORKER_FAILED",
            format!("The scan worker stopped unexpectedly: {error}"),
            true,
        )
    })??;
    let settings = state
        .settings
        .lock()
        .map_err(|_| internal_state_failure())?
        .clone();
    output.analyzer.apply_settings(&output.arena, &settings);
    let summary = output.summary.clone();
    *state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())? = Some(Arc::new(RwLock::new(output)));
    *state.plan.lock().map_err(|_| internal_state_failure())? = None;
    Ok(summary)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, ScannerState>) -> Result<bool, ScanFailure> {
    let active = state.active.lock().map_err(|_| internal_state_failure())?;
    let Some(scan) = active.as_ref() else {
        return Ok(false);
    };
    scan.cancel.store(true, Ordering::Relaxed);
    Ok(true)
}

#[tauri::command]
pub fn get_scan_summary(
    state: State<'_, ScannerState>,
) -> Result<Option<ScanSummary>, ScanFailure> {
    let output = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?
        .clone();
    output
        .map(|output| {
            output
                .read()
                .map(|output| output.summary.clone())
                .map_err(|_| internal_state_failure())
        })
        .transpose()
}

#[tauri::command]
pub async fn query_items(
    session_id: String,
    query: ItemQuery,
    state: State<'_, ScannerState>,
) -> Result<ItemPage, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let token = Arc::new(AtomicBool::new(false));
    let query_key = query
        .query_id
        .as_ref()
        .map(|query_id| (session_id.clone(), query_id.clone()));
    if let Some(key) = &query_key {
        let mut queries = state.queries.lock().map_err(|_| internal_state_failure())?;
        if queries.contains_key(key) {
            return Err(ScanFailure::new(
                "QUERY_ALREADY_RUNNING",
                "A query with this query_id is already running",
                true,
            ));
        }
        queries.insert(key.clone(), Arc::clone(&token));
    }
    let worker = tauri::async_runtime::spawn_blocking(move || {
        let output = output.read().map_err(|_| internal_state_failure())?;
        output
            .analyzer
            .query_cancellable(&output.arena, &query, &token)
    })
    .await;
    if let Some(key) = query_key {
        state
            .queries
            .lock()
            .map_err(|_| internal_state_failure())?
            .remove(&key);
    }
    worker.map_err(|error| {
        ScanFailure::new(
            "QUERY_WORKER_FAILED",
            format!("The analyzer query worker stopped unexpectedly: {error}"),
            true,
        )
    })?
}

#[tauri::command]
pub fn cancel_item_query(
    session_id: String,
    query_id: String,
    state: State<'_, ScannerState>,
) -> Result<bool, ScanFailure> {
    let queries = state.queries.lock().map_err(|_| internal_state_failure())?;
    let Some(cancel) = queries.get(&(session_id, query_id)) else {
        return Ok(false);
    };
    cancel.store(true, Ordering::Release);
    Ok(true)
}

#[tauri::command]
pub fn get_item_details(
    session_id: String,
    node_id: String,
    state: State<'_, ScannerState>,
) -> Result<ItemDetails, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let output = output.read().map_err(|_| internal_state_failure())?;
    output.analyzer.item_details(&output.arena, &node_id)
}

#[tauri::command]
pub async fn inspect_log_excerpt(
    session_id: String,
    request: LogExcerptRequest,
    state: State<'_, ScannerState>,
) -> Result<LogExcerptBatch, ScanFailure> {
    validate_log_request(&request)?;
    let output = completed_output(&state, &session_id)?;
    let eligible = {
        let output = output.read().map_err(|_| internal_state_failure())?;
        request
            .item_ids
            .iter()
            .map(|item_id| {
                let details = output.analyzer.item_details(&output.arena, item_id)?;
                validate_log_item(&details)?;
                Ok((item_id.clone(), PathBuf::from(details.item.display_path)))
            })
            .collect::<Result<Vec<_>, ScanFailure>>()?
    };
    let requested_bytes = request.requested_bytes_per_file as usize;
    tauri::async_runtime::spawn_blocking(move || read_log_excerpts(eligible, requested_bytes))
        .await
        .map_err(|error| {
            ScanFailure::new(
                "LOG_READ_WORKER_FAILED",
                format!("The bounded log reader stopped unexpectedly: {error}"),
                true,
            )
        })?
}

fn validate_log_request(request: &LogExcerptRequest) -> Result<(), ScanFailure> {
    if request.item_ids.is_empty() || request.item_ids.len() > MAX_LOG_EXCERPT_FILES {
        return Err(ScanFailure::new(
            "LOG_EXCERPT_LIMIT",
            "Log inspection requires between one and five exact item IDs",
            true,
        ));
    }
    let requested = request.requested_bytes_per_file as usize;
    if requested == 0
        || requested > MAX_LOG_EXCERPT_BYTES_PER_FILE
        || requested.saturating_mul(request.item_ids.len()) > MAX_LOG_EXCERPT_TOTAL_BYTES
    {
        return Err(ScanFailure::new(
            "LOG_EXCERPT_LIMIT",
            "Log inspection is limited to 64 KiB per file and 256 KiB total",
            true,
        ));
    }
    let mut unique = request.item_ids.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != request.item_ids.len() {
        return Err(ScanFailure::new(
            "LOG_EXCERPT_LIMIT",
            "Log inspection item IDs must be unique",
            true,
        ));
    }
    Ok(())
}

fn validate_log_item(details: &ItemDetails) -> Result<(), ScanFailure> {
    const TEXT_LOG_EXTENSIONS: &[&str] = &["log", "txt", "out", "err", "trace", "wer"];
    const LOG_RULES: &[&str] = &["cleanup.crash_reports", "cleanup.npm_logs"];
    let extension = details
        .item
        .extension
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if details.item.kind != clutter_core::scan::ItemKind::File
        || details.evidence.tier != PolicyTier::CleanupCandidate
        || !LOG_RULES.contains(&details.evidence.rule_id.as_str())
        || !TEXT_LOG_EXTENSIONS.contains(&extension.as_str())
        || details
            .item
            .attributes
            .iter()
            .any(|attribute| attribute == "encrypted" || attribute == "reparse_point")
    {
        return Err(ScanFailure::new(
            "LOG_NOT_ELIGIBLE",
            format!(
                "{} is not a recognized, unprotected text log",
                details.item.display_path
            ),
            false,
        ));
    }
    Ok(())
}

fn read_log_excerpts(
    items: Vec<(String, PathBuf)>,
    requested_bytes: usize,
) -> Result<LogExcerptBatch, ScanFailure> {
    let mut excerpts = Vec::with_capacity(items.len());
    let mut total_returned = 0usize;
    for (item_id, path) in items {
        let mut file = open_log_file(&path).map_err(|error| log_read_failure(&path, error))?;
        let before = file
            .metadata()
            .map_err(|error| log_read_failure(&path, error))?;
        if !before.is_file() {
            return Err(ScanFailure::new(
                "LOG_NOT_ELIGIBLE",
                format!("{} is no longer a regular file", path.display()),
                false,
            ));
        }
        let original_bytes = before.len();
        let (bytes, truncated) = read_bounded_start_end(&mut file, original_bytes, requested_bytes)
            .map_err(|error| log_read_failure(&path, error))?;
        let after = file
            .metadata()
            .map_err(|error| log_read_failure(&path, error))?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err(ScanFailure::new(
                "LOG_CHANGED_DURING_READ",
                format!("{} changed during bounded inspection", path.display()),
                true,
            ));
        }
        let (content, encoding) = decode_text_log(&bytes).ok_or_else(|| {
            ScanFailure::new(
                "LOG_NOT_TEXT",
                format!("{} did not contain supported text", path.display()),
                false,
            )
        })?;
        total_returned = total_returned.saturating_add(bytes.len());
        excerpts.push(LogExcerpt {
            item_id,
            display_path: path.to_string_lossy().into_owned(),
            encoding: encoding.to_owned(),
            content,
            original_bytes: original_bytes.to_string(),
            returned_bytes: bytes.len().to_string(),
            truncated,
        });
    }
    Ok(LogExcerptBatch {
        excerpts,
        total_returned_bytes: total_returned.to_string(),
    })
}

fn read_bounded_start_end(
    file: &mut std::fs::File,
    length: u64,
    maximum: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    if length <= maximum as u64 {
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(maximum as u64).read_to_end(&mut bytes)?;
        return Ok((bytes, false));
    }
    let mut prefix = [0u8; 3];
    let prefix_length = file.read(&mut prefix)?;
    file.seek(std::io::SeekFrom::Start(0))?;
    let utf16 = prefix_length >= 2 && matches!(&prefix[..2], [0xff, 0xfe] | [0xfe, 0xff]);
    let marker = truncation_marker(&prefix[..prefix_length]);
    let content_budget = maximum.saturating_sub(marker.len());
    let mut beginning_bytes = content_budget / 2;
    let mut ending_bytes = content_budget - beginning_bytes;
    if utf16 {
        beginning_bytes &= !1;
        ending_bytes &= !1;
    }
    let mut bytes = Vec::with_capacity(maximum);
    file.take(beginning_bytes as u64).read_to_end(&mut bytes)?;
    bytes.extend_from_slice(&marker);
    file.seek(std::io::SeekFrom::Start(length - ending_bytes as u64))?;
    file.take(ending_bytes as u64).read_to_end(&mut bytes)?;
    Ok((bytes, true))
}

fn truncation_marker(prefix: &[u8]) -> Vec<u8> {
    const TEXT: &str = "\n...[truncated]...\n";
    if prefix.starts_with(&[0xff, 0xfe]) {
        TEXT.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else if prefix.starts_with(&[0xfe, 0xff]) {
        TEXT.encode_utf16().flat_map(u16::to_be_bytes).collect()
    } else {
        TEXT.as_bytes().to_vec()
    }
}

fn decode_text_log(bytes: &[u8]) -> Option<(String, &'static str)> {
    let (text, encoding) = if bytes.starts_with(&[0xff, 0xfe]) {
        let words = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        (String::from_utf16(&words).ok()?, "utf-16le")
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        let words = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        (String::from_utf16(&words).ok()?, "utf-16be")
    } else {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        if bytes.contains(&0) {
            return None;
        }
        (String::from_utf8_lossy(bytes).into_owned(), "utf-8")
    };
    let controls = text
        .chars()
        .filter(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        .count();
    let replacements = text
        .chars()
        .filter(|character| *character == '\u{fffd}')
        .count();
    let characters = text.chars().count().max(1);
    if controls.saturating_mul(100) > characters || replacements.saturating_mul(100) > characters {
        return None;
    }
    Some((text, encoding))
}

#[cfg(windows)]
fn open_log_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    };

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN).0)
        .open(path)
}

#[cfg(not(windows))]
fn open_log_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn log_read_failure(path: &Path, error: std::io::Error) -> ScanFailure {
    ScanFailure::new(
        "LOG_READ_FAILED",
        format!("Could not read {}: {error}", path.display()),
        true,
    )
}

#[tauri::command]
pub fn get_storage_aggregate(
    session_id: String,
    query: StorageAggregateQuery,
    state: State<'_, ScannerState>,
) -> Result<StorageAggregate, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let output = output.read().map_err(|_| internal_state_failure())?;
    output.analyzer.aggregate(&output.arena, &query)
}

#[tauri::command]
pub fn get_treemap_slice(
    session_id: String,
    query: TreemapQuery,
    state: State<'_, ScannerState>,
) -> Result<TreemapSlice, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let output = output.read().map_err(|_| internal_state_failure())?;
    output.analyzer.treemap(&output.arena, &query)
}

#[tauri::command]
pub fn build_cleanup_plan(
    session_id: String,
    request: CleanupPlanRequest,
    state: State<'_, ScannerState>,
) -> Result<CleanupPlan, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let output = output.read().map_err(|_| internal_state_failure())?;
    let plan = output.analyzer.build_plan(&output.arena, &request)?;
    *state.plan.lock().map_err(|_| internal_state_failure())? = Some(plan.clone());
    Ok(plan)
}

#[tauri::command]
pub fn edit_cleanup_plan(
    session_id: String,
    edit: PlanEdit,
    state: State<'_, ScannerState>,
) -> Result<CleanupPlan, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let output = output.read().map_err(|_| internal_state_failure())?;
    let mut plan = state.plan.lock().map_err(|_| internal_state_failure())?;
    let plan = plan.as_mut().ok_or_else(|| {
        ScanFailure::new(
            "NO_CLEANUP_PLAN",
            "Build a cleanup plan before editing it",
            true,
        )
    })?;
    output.analyzer.edit_plan(&output.arena, plan, &edit)?;
    Ok(plan.clone())
}

#[tauri::command]
pub fn set_path_protection(
    session_id: String,
    request: PathProtectionRequest,
    state: State<'_, ScannerState>,
) -> Result<PolicyEvidence, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let mut output = output.write().map_err(|_| internal_state_failure())?;
    let key = output
        .analyzer
        .protection_key(&output.arena, &request.node_id)?;
    let mut settings = state
        .settings
        .lock()
        .map_err(|_| internal_state_failure())?;
    let mut updated = settings.clone();
    if request.protected {
        if !updated.protected_paths.contains(&key) {
            updated.protected_paths.push(key);
            updated.protected_paths.sort();
        }
    } else {
        updated.protected_paths.retain(|path| path != &key);
    }
    save_analyzer_settings(&updated)?;
    *settings = updated;
    let ScanOutput {
        arena, analyzer, ..
    } = &mut *output;
    analyzer.apply_settings(arena, &settings);
    let evidence = analyzer.item_details(arena, &request.node_id)?.evidence;
    *state.plan.lock().map_err(|_| internal_state_failure())? = None;
    Ok(evidence)
}

#[tauri::command]
pub fn dismiss_suggestion(
    session_id: String,
    request: DismissSuggestionRequest,
    state: State<'_, ScannerState>,
) -> Result<bool, ScanFailure> {
    let output = completed_output(&state, &session_id)?;
    let mut output = output.write().map_err(|_| internal_state_failure())?;
    let key = output.analyzer.dismissal_key(&output.arena, &request)?;
    let mut settings = state
        .settings
        .lock()
        .map_err(|_| internal_state_failure())?;
    let mut updated = settings.clone();
    if request.dismissed {
        if !updated.dismissed_suggestions.contains(&key) {
            updated.dismissed_suggestions.push(key);
            updated.dismissed_suggestions.sort_by(|left, right| {
                left.canonical_path
                    .cmp(&right.canonical_path)
                    .then_with(|| left.rule_id.cmp(&right.rule_id))
            });
        }
    } else {
        updated
            .dismissed_suggestions
            .retain(|suggestion| suggestion != &key);
    }
    save_analyzer_settings(&updated)?;
    *settings = updated;
    let ScanOutput {
        arena, analyzer, ..
    } = &mut *output;
    analyzer.apply_settings(arena, &settings);
    let dismissed = request.dismissed;
    *state.plan.lock().map_err(|_| internal_state_failure())? = None;
    Ok(dismissed)
}

#[tauri::command]
pub fn delete_file_item(path: String) -> Result<bool, String> {
    let target = Path::new(&path);
    if !target.exists() {
        return Err(format!("File or folder does not exist: {}", path));
    }
    if target.is_dir() {
        std::fs::remove_dir_all(target).map_err(|error| format!("Failed to delete directory {}: {}", path, error))?;
    } else {
        std::fs::remove_file(target).map_err(|error| format!("Failed to delete file {}: {}", path, error))?;
    }
    Ok(true)
}

fn completed_output(
    state: &ScannerState,
    session_id: &str,
) -> Result<Arc<RwLock<ScanOutput>>, ScanFailure> {
    let output = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?
        .clone()
        .ok_or_else(|| ScanFailure::new("STALE_SESSION", "No completed scan is available", true))?;
    if output
        .read()
        .map_err(|_| internal_state_failure())?
        .summary
        .session_id
        != session_id
    {
        return Err(stale_session_failure());
    }
    Ok(output)
}

fn cancel_active_queries(state: &ScannerState) -> Result<(), ScanFailure> {
    let queries = state.queries.lock().map_err(|_| internal_state_failure())?;
    for cancel in queries.values() {
        cancel.store(true, Ordering::Release);
    }
    Ok(())
}

fn stale_session_failure() -> ScanFailure {
    ScanFailure::new(
        "STALE_SESSION",
        "The requested scan is no longer active",
        true,
    )
}

fn internal_state_failure() -> ScanFailure {
    ScanFailure::new(
        "INTERNAL_STATE",
        "The scanner state could not be accessed",
        true,
    )
}

fn analyzer_settings_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("ClutterHunter").join("policy-settings.json"))
}

fn load_analyzer_settings() -> AnalyzerSettings {
    let Some(path) = analyzer_settings_path() else {
        return AnalyzerSettings::default();
    };
    load_analyzer_settings_from(&path)
}

fn load_analyzer_settings_from(path: &Path) -> AnalyzerSettings {
    let Ok(bytes) = std::fs::read(path) else {
        return AnalyzerSettings::default();
    };
    if bytes.len() > MAX_ANALYZER_SETTINGS_BYTES {
        return AnalyzerSettings::default();
    }
    serde_json::from_slice::<AnalyzerSettings>(&bytes)
        .unwrap_or_default()
        .normalized()
}

fn save_analyzer_settings(settings: &AnalyzerSettings) -> Result<(), ScanFailure> {
    let path = analyzer_settings_path().ok_or_else(|| {
        ScanFailure::new(
            "SETTINGS_PATH_UNAVAILABLE",
            "Windows did not provide a local application data directory",
            true,
        )
    })?;
    save_analyzer_settings_to(&path, settings)
}

fn save_analyzer_settings_to(path: &Path, settings: &AnalyzerSettings) -> Result<(), ScanFailure> {
    let parent = path.parent().ok_or_else(|| {
        ScanFailure::new(
            "SETTINGS_PATH_UNAVAILABLE",
            "The analyzer settings directory was invalid",
            true,
        )
    })?;
    std::fs::create_dir_all(parent).map_err(settings_write_failure)?;
    let settings = settings.clone().normalized();
    let bytes = serde_json::to_vec_pretty(&settings).map_err(|error| {
        ScanFailure::new(
            "SETTINGS_WRITE_FAILED",
            format!("Could not encode analyzer settings: {error}"),
            true,
        )
    })?;
    if bytes.len() > MAX_ANALYZER_SETTINGS_BYTES {
        return Err(ScanFailure::new(
            "SETTINGS_TOO_LARGE",
            "Analyzer settings exceeded the local storage limit",
            true,
        ));
    }

    let counter = SETTINGS_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy-settings.json");
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{counter}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_settings_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(settings_write_failure)
}

#[cfg(windows)]
fn replace_settings_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows::{
        Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        core::PCWSTR,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(std::io::Error::other)
}

#[cfg(not(windows))]
fn replace_settings_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

fn settings_write_failure(error: std::io::Error) -> ScanFailure {
    ScanFailure::new(
        "SETTINGS_WRITE_FAILED",
        format!("Could not save analyzer settings: {error}"),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_migrates_legacy_paths_and_deduplicates() {
        let fixture = TempSettings::new();
        std::fs::write(
            &fixture.path,
            br#"{
                "protected_paths": ["C:/Data/", "c:\\data"],
                "dismissed_suggestions": [
                    {"canonical_path": "C:/Temp/", "rule_id": "cleanup.user_temp"},
                    {"canonical_path": "c:\\temp", "rule_id": "cleanup.user_temp"}
                ]
            }"#,
        )
        .unwrap();

        let loaded = load_analyzer_settings_from(&fixture.path);
        assert_eq!(
            loaded.protected_paths,
            vec![clutter_core::analyzer::ProtectedPath::Absolute {
                absolute_path: r"c:\data".to_owned()
            }]
        );
        assert_eq!(loaded.dismissed_suggestions.len(), 1);

        save_analyzer_settings_to(&fixture.path, &loaded).unwrap();
        assert_eq!(load_analyzer_settings_from(&fixture.path), loaded);
    }

    #[test]
    fn oversized_or_malformed_settings_fail_closed_to_defaults() {
        let fixture = TempSettings::new();
        std::fs::write(&fixture.path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert_eq!(
            load_analyzer_settings_from(&fixture.path),
            AnalyzerSettings::default()
        );
        std::fs::write(&fixture.path, b"not-json").unwrap();
        assert_eq!(
            load_analyzer_settings_from(&fixture.path),
            AnalyzerSettings::default()
        );
    }

    #[test]
    fn oversized_settings_write_preserves_the_previous_file() {
        let fixture = TempSettings::new();
        let original = AnalyzerSettings::default();
        save_analyzer_settings_to(&fixture.path, &original).unwrap();
        let previous_bytes = std::fs::read(&fixture.path).unwrap();
        let oversized = AnalyzerSettings {
            protected_paths: (0..20_000)
                .map(|index| clutter_core::analyzer::ProtectedPath::Absolute {
                    absolute_path: format!(
                        r"c:\very-long-protected-settings-fixture\{index:08}\{}",
                        "x".repeat(48)
                    ),
                })
                .collect(),
            dismissed_suggestions: Vec::new(),
        };

        let error = save_analyzer_settings_to(&fixture.path, &oversized).unwrap_err();
        assert_eq!(error.code, "SETTINGS_TOO_LARGE");
        assert_eq!(std::fs::read(&fixture.path).unwrap(), previous_bytes);
        assert_eq!(load_analyzer_settings_from(&fixture.path), original);
    }

    #[test]
    fn starting_a_scan_cancels_every_active_query() {
        let state = ScannerState {
            active: Mutex::new(None),
            completed: Mutex::new(None),
            queries: Mutex::new(HashMap::new()),
            plan: Mutex::new(None),
            settings: Mutex::new(AnalyzerSettings::default()),
        };
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        state.queries.lock().unwrap().insert(
            ("scan-a".to_owned(), "query-a".to_owned()),
            Arc::clone(&first),
        );
        state.queries.lock().unwrap().insert(
            ("scan-a".to_owned(), "query-b".to_owned()),
            Arc::clone(&second),
        );

        cancel_active_queries(&state).unwrap();

        assert!(first.load(Ordering::Acquire));
        assert!(second.load(Ordering::Acquire));
    }

    #[cfg(windows)]
    #[test]
    fn hardware_profile_reports_physical_memory() {
        let profile = hardware_profile().unwrap();
        let total = profile.total_memory_bytes.parse::<u64>().unwrap();
        let available = profile.available_memory_bytes.parse::<u64>().unwrap();
        assert!(total > 0);
        assert!(available <= total);
    }

    #[test]
    fn log_excerpt_limits_and_text_decoding_are_bounded() {
        assert!(
            validate_log_request(&LogExcerptRequest {
                item_ids: vec!["one".to_owned(), "two".to_owned()],
                requested_bytes_per_file: 64 * 1024,
            })
            .is_ok()
        );
        assert_eq!(
            validate_log_request(&LogExcerptRequest {
                item_ids: vec!["same".to_owned(), "same".to_owned()],
                requested_bytes_per_file: 1024,
            })
            .unwrap_err()
            .code,
            "LOG_EXCERPT_LIMIT"
        );

        let mut path = TempSettings::new();
        path.path.set_file_name("fixture.log");
        let content = "begin\n".to_owned() + &"x".repeat(10_000) + "\nend";
        std::fs::write(&path.path, content).unwrap();
        let mut file = std::fs::File::open(&path.path).unwrap();
        let (bytes, truncated) = read_bounded_start_end(&mut file, 10_010, 1024).unwrap();
        assert!(truncated);
        assert!(bytes.len() <= 1024);
        let (decoded, encoding) = decode_text_log(&bytes).unwrap();
        assert_eq!(encoding, "utf-8");
        assert!(decoded.contains("[truncated]"));

        let utf16 = [0xff, 0xfe, b'O', 0, b'K', 0];
        assert_eq!(decode_text_log(&utf16), Some(("OK".to_owned(), "utf-16le")));
        let mut utf16_log = vec![0xff, 0xfe];
        utf16_log.extend("start\n".encode_utf16().flat_map(u16::to_le_bytes));
        utf16_log.extend("x".repeat(2_000).encode_utf16().flat_map(u16::to_le_bytes));
        utf16_log.extend("\nend".encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&path.path, &utf16_log).unwrap();
        let mut file = std::fs::File::open(&path.path).unwrap();
        let (bytes, truncated) =
            read_bounded_start_end(&mut file, utf16_log.len() as u64, 512).unwrap();
        assert!(truncated);
        let (decoded, encoding) = decode_text_log(&bytes).unwrap();
        assert_eq!(encoding, "utf-16le");
        assert!(decoded.contains("[truncated]"));
        assert!(decode_text_log(&[0, 1, 2, 3, 4, 5]).is_none());
    }

    struct TempSettings {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TempSettings {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "clutterhunter-settings-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join("policy-settings.json");
            Self { directory, path }
        }
    }

    impl Drop for TempSettings {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}
