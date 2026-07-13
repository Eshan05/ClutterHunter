use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use clutter_core::{
    analyzer::AnalyzerSettings,
    backend::{ScanOutput, new_session_id, run_scan},
    scan::{
        CleanupPlan, CleanupPlanRequest, DismissSuggestionRequest, ItemDetails, ItemPage,
        ItemQuery, PathProtectionRequest, PlanEdit, PolicyEvidence, ScanFailure, ScanProgress,
        ScanRequest, ScanSummary, ScanTarget, StorageAggregate, StorageAggregateQuery,
        TreemapQuery, TreemapSlice, default_scan_targets,
    },
};
use tauri::{State, ipc::Channel};

pub struct ScannerState {
    active: Mutex<Option<ActiveScan>>,
    completed: Mutex<Option<ScanOutput>>,
    plan: Mutex<Option<CleanupPlan>>,
    settings: Mutex<AnalyzerSettings>,
}

impl Default for ScannerState {
    fn default() -> Self {
        Self {
            active: Mutex::new(None),
            completed: Mutex::new(None),
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
pub async fn start_scan(
    request: ScanRequest,
    on_progress: Channel<ScanProgress>,
    state: State<'_, ScannerState>,
) -> Result<ScanSummary, ScanFailure> {
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
        .map_err(|_| internal_state_failure())? = Some(output);
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
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    Ok(completed.as_ref().map(|output| output.summary.clone()))
}

#[tauri::command]
pub fn query_items(
    session_id: String,
    query: ItemQuery,
    state: State<'_, ScannerState>,
) -> Result<ItemPage, ScanFailure> {
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = completed
        .as_ref()
        .ok_or_else(|| ScanFailure::new("STALE_SESSION", "No completed scan is available", true))?;
    if output.summary.session_id != session_id {
        return Err(ScanFailure::new(
            "STALE_SESSION",
            "The requested scan is no longer active",
            true,
        ));
    }
    output.analyzer.query(&output.arena, &query)
}

#[tauri::command]
pub fn get_item_details(
    session_id: String,
    node_id: String,
    state: State<'_, ScannerState>,
) -> Result<ItemDetails, ScanFailure> {
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output(&completed, &session_id)?;
    output.analyzer.item_details(&output.arena, &node_id)
}

#[tauri::command]
pub fn get_storage_aggregate(
    session_id: String,
    query: StorageAggregateQuery,
    state: State<'_, ScannerState>,
) -> Result<StorageAggregate, ScanFailure> {
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output(&completed, &session_id)?;
    output.analyzer.aggregate(&output.arena, &query)
}

#[tauri::command]
pub fn get_treemap_slice(
    session_id: String,
    query: TreemapQuery,
    state: State<'_, ScannerState>,
) -> Result<TreemapSlice, ScanFailure> {
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output(&completed, &session_id)?;
    output.analyzer.treemap(&output.arena, &query)
}

#[tauri::command]
pub fn build_cleanup_plan(
    session_id: String,
    request: CleanupPlanRequest,
    state: State<'_, ScannerState>,
) -> Result<CleanupPlan, ScanFailure> {
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output(&completed, &session_id)?;
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
    let completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output(&completed, &session_id)?;
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
    let mut completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output_mut(&mut completed, &session_id)?;
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
    output.analyzer.apply_settings(&output.arena, &settings);
    let evidence = output
        .analyzer
        .item_details(&output.arena, &request.node_id)?
        .evidence;
    *state.plan.lock().map_err(|_| internal_state_failure())? = None;
    Ok(evidence)
}

#[tauri::command]
pub fn dismiss_suggestion(
    session_id: String,
    request: DismissSuggestionRequest,
    state: State<'_, ScannerState>,
) -> Result<bool, ScanFailure> {
    let mut completed = state
        .completed
        .lock()
        .map_err(|_| internal_state_failure())?;
    let output = active_output_mut(&mut completed, &session_id)?;
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
    output.analyzer.apply_settings(&output.arena, &settings);
    let dismissed = request.dismissed;
    *state.plan.lock().map_err(|_| internal_state_failure())? = None;
    Ok(dismissed)
}

fn active_output<'a>(
    completed: &'a Option<ScanOutput>,
    session_id: &str,
) -> Result<&'a ScanOutput, ScanFailure> {
    let output = completed
        .as_ref()
        .ok_or_else(|| ScanFailure::new("STALE_SESSION", "No completed scan is available", true))?;
    if output.summary.session_id != session_id {
        return Err(stale_session_failure());
    }
    Ok(output)
}

fn active_output_mut<'a>(
    completed: &'a mut Option<ScanOutput>,
    session_id: &str,
) -> Result<&'a mut ScanOutput, ScanFailure> {
    let output = completed
        .as_mut()
        .ok_or_else(|| ScanFailure::new("STALE_SESSION", "No completed scan is available", true))?;
    if output.summary.session_id != session_id {
        return Err(stale_session_failure());
    }
    Ok(output)
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
    let Ok(bytes) = std::fs::read(path) else {
        return AnalyzerSettings::default();
    };
    if bytes.len() > 1024 * 1024 {
        return AnalyzerSettings::default();
    }
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_analyzer_settings(settings: &AnalyzerSettings) -> Result<(), ScanFailure> {
    let path = analyzer_settings_path().ok_or_else(|| {
        ScanFailure::new(
            "SETTINGS_PATH_UNAVAILABLE",
            "Windows did not provide a local application data directory",
            true,
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        ScanFailure::new(
            "SETTINGS_PATH_UNAVAILABLE",
            "The analyzer settings directory was invalid",
            true,
        )
    })?;
    std::fs::create_dir_all(parent).map_err(settings_write_failure)?;
    let bytes = serde_json::to_vec_pretty(settings).map_err(|error| {
        ScanFailure::new(
            "SETTINGS_WRITE_FAILED",
            format!("Could not encode analyzer settings: {error}"),
            true,
        )
    })?;
    std::fs::write(path, bytes).map_err(settings_write_failure)
}

fn settings_write_failure(error: std::io::Error) -> ScanFailure {
    ScanFailure::new(
        "SETTINGS_WRITE_FAILED",
        format!("Could not save analyzer settings: {error}"),
        true,
    )
}
