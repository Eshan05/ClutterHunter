use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum ScanTargetKind {
    Volume,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum ScanBackend {
    RawNtfs,
    Traversal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum ScanPhase {
    Preparing,
    Elevating,
    Enumerating,
    Indexing,
    Classifying,
    Finalizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum ScanCoverage {
    Complete,
    Partial,
    PotentiallyStale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ScanTarget {
    pub id: String,
    pub kind: ScanTargetKind,
    pub display_path: String,
    pub filesystem: Option<String>,
    pub volume_id: Option<String>,
    pub total_bytes: Option<String>,
    pub available_bytes: Option<String>,
    pub fast_scan_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ScanRequest {
    pub target: ScanTarget,
    pub preferred_backend: ScanBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ScanWarning {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ScanFailure {
    pub code: String,
    pub detail: String,
    pub recoverable: bool,
}

impl ScanFailure {
    pub fn new(code: impl Into<String>, detail: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
            recoverable,
        }
    }
}

impl std::fmt::Display for ScanFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ScanFailure {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ScanProgress {
    pub session_id: String,
    pub phase: ScanPhase,
    pub backend: ScanBackend,
    pub entries_seen: String,
    pub bytes_accounted: String,
    pub elapsed_ms: String,
    pub warnings: Vec<ScanWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ScanSummary {
    pub session_id: String,
    pub target: ScanTarget,
    pub backend: ScanBackend,
    pub coverage: ScanCoverage,
    pub entry_count: String,
    pub logical_bytes: String,
    pub allocated_bytes: String,
    pub volume_used_bytes: Option<String>,
    pub unaccounted_bytes: Option<String>,
    pub elapsed_ms: String,
    pub warnings: Vec<ScanWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum ItemKind {
    File,
    Directory,
    ReparsePoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum ItemSort {
    Name,
    Allocated,
    Logical,
    Modified,
    Type,
    Policy,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ItemQuery {
    pub parent_id: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub scope_id: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub text: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub kinds: Option<Vec<ItemKind>>,
    #[serde(default)]
    #[ts(optional)]
    pub extensions: Option<Vec<String>>,
    #[serde(default)]
    #[ts(optional)]
    pub policy_tiers: Option<Vec<PolicyTier>>,
    #[serde(default)]
    #[ts(optional)]
    pub owner_ids: Option<Vec<String>>,
    #[serde(default)]
    #[ts(optional)]
    pub min_bytes: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub modified_before_ms: Option<String>,
    pub sort: ItemSort,
    pub direction: SortDirection,
    pub cursor: Option<String>,
    pub limit: u16,
}

impl Default for ItemQuery {
    fn default() -> Self {
        Self {
            parent_id: None,
            scope_id: None,
            text: None,
            kinds: None,
            extensions: None,
            policy_tiers: None,
            owner_ids: None,
            min_bytes: None,
            modified_before_ms: None,
            sort: ItemSort::Name,
            direction: SortDirection::Asc,
            cursor: None,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ItemRow {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub display_path: String,
    pub kind: ItemKind,
    pub logical_bytes: String,
    pub allocated_bytes: String,
    pub modified_at_ms: Option<String>,
    pub extension: Option<String>,
    pub attributes: Vec<String>,
    pub hard_link_count: Option<u32>,
    pub child_count: Option<u32>,
    pub owner: Option<OwnerSummary>,
    pub policy: PolicyEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ItemPage {
    pub items: Vec<ItemRow>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum PolicyTier {
    Protected,
    ReviewRequired,
    CleanupCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum OwnerSource {
    Registry,
    Appx,
    KnownRoot,
    BundledMapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum OwnerMatchKind {
    Exact,
    Prefix,
    Inference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct OwnerSummary {
    pub id: String,
    pub name: String,
    pub source: OwnerSource,
    pub match_kind: OwnerMatchKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct PolicyEvidence {
    pub tier: PolicyTier,
    pub rule_id: String,
    pub rule_version: String,
    pub facts: Vec<String>,
    pub inference: Vec<String>,
    pub warnings: Vec<String>,
}

impl Default for PolicyEvidence {
    fn default() -> Self {
        Self {
            tier: PolicyTier::Protected,
            rule_id: "protected.unknown".to_owned(),
            rule_version: "1".to_owned(),
            facts: vec!["No narrow cleanup rule matched this item".to_owned()],
            inference: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct ItemDetails {
    pub item: ItemRow,
    pub evidence: PolicyEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum AggregateDimension {
    Extension,
    Owner,
    Policy,
    Kind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct StorageAggregateQuery {
    pub scope_id: Option<String>,
    pub dimension: AggregateDimension,
    pub limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct StorageBucket {
    pub key: String,
    pub label: String,
    pub item_count: String,
    pub logical_bytes: String,
    pub allocated_bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct StorageAggregate {
    pub buckets: Vec<StorageBucket>,
    pub other_item_count: String,
    pub other_logical_bytes: String,
    pub other_allocated_bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct TreemapQuery {
    pub scope_id: Option<String>,
    pub max_nodes: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct TreemapNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub allocated_bytes: String,
    pub kind: ItemKind,
    pub policy_tier: PolicyTier,
    pub owner_id: Option<String>,
    pub synthetic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct TreemapSlice {
    pub nodes: Vec<TreemapNode>,
    pub truncated: bool,
    pub other_allocated_bytes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../src/bindings/")]
pub enum PlanActionKind {
    Inspect,
    OpenLocation,
    OpenWindowsAppsSettings,
    OpenWindowsStorageSettings,
    RunOllamaRm,
    RunScoopCleanup,
    RunScoopCache,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct CleanupPlanRequest {
    pub target_bytes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct PlanItem {
    pub id: String,
    pub node_ids: Vec<String>,
    pub title: String,
    pub category: String,
    pub tier: PolicyTier,
    pub selected: bool,
    pub reclaimable_bytes: String,
    pub evidence: Vec<PolicyEvidence>,
    pub warnings: Vec<String>,
    pub action_kind: PlanActionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct CleanupPlan {
    pub session_id: String,
    pub target_bytes: Option<String>,
    pub selected_candidate_bytes: String,
    pub selected_review_bytes: String,
    pub review_potential_bytes: String,
    pub target_shortfall_bytes: String,
    pub items: Vec<PlanItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct PlanEdit {
    pub item_id: String,
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct PathProtectionRequest {
    pub node_id: String,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../src/bindings/")]
pub struct DismissSuggestionRequest {
    pub node_id: String,
    pub rule_id: String,
    pub dismissed: bool,
}

pub fn default_scan_targets() -> Vec<ScanTarget> {
    crate::volume::scan_targets()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_target_is_a_volume() {
        let targets = default_scan_targets();

        assert!(!targets.is_empty());
        assert_eq!(targets[0].kind, ScanTargetKind::Volume);
        assert!(targets[0].display_path.ends_with(['\\', '/']));
    }

    #[test]
    fn failure_has_a_stable_code() {
        let failure = ScanFailure::new("SCAN_CANCELLED", "Cancelled by user", true);

        assert_eq!(failure.code, "SCAN_CANCELLED");
        assert!(failure.recoverable);
    }
}
