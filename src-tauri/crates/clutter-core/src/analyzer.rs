use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
};

use serde::{Deserialize, Serialize};

use crate::{
    arena::{ArenaNode, NO_INDEX, ScanArena},
    ownership::{OwnerRecord, canonical_path, discover_owners},
    scan::{
        AggregateDimension, CleanupPlan, CleanupPlanRequest, DismissSuggestionRequest, ItemDetails,
        ItemKind, ItemPage, ItemQuery, ItemRow, ItemSort, OwnerMatchKind, OwnerSummary,
        PathProtectionRequest, PlanActionKind, PlanEdit, PlanItem, PolicyEvidence, PolicyTier,
        ScanCoverage, ScanFailure, ScanTarget, SortDirection, StorageAggregate,
        StorageAggregateQuery, StorageBucket, TreemapNode, TreemapQuery, TreemapSlice,
    },
};

const RULE_VERSION: &str = "1";
const NO_OWNER: u32 = u32::MAX;
const MAX_CACHED_SORT_INDICES: usize = 8_000_000;
const MAX_PLAN_ITEMS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
enum Rule {
    Unknown,
    ScanRoot,
    System,
    InstalledApplication,
    PersonalData,
    SourceData,
    EncryptedData,
    BackupData,
    UserProtected,
    MixedContent,
    GeneratedProjectData,
    RecycleBin,
    WindowsManagedCleanup,
    UserTemp,
    BrowserCache,
    CrashReports,
    ScoopCache,
    NpmCache,
    NpmLogs,
    OllamaModels,
    OllamaBlobs,
}

impl Rule {
    fn id(self) -> &'static str {
        match self {
            Self::Unknown => "protected.unknown",
            Self::ScanRoot => "protected.scan_root",
            Self::System => "protected.system",
            Self::InstalledApplication => "protected.installed_application",
            Self::PersonalData => "protected.personal_data",
            Self::SourceData => "protected.source_data",
            Self::EncryptedData => "protected.encrypted_data",
            Self::BackupData => "protected.backup_data",
            Self::UserProtected => "protected.user_path",
            Self::MixedContent => "protected.mixed_cleanup_content",
            Self::GeneratedProjectData => "review.generated_project_data",
            Self::RecycleBin => "review.recycle_bin",
            Self::WindowsManagedCleanup => "review.windows_managed_cleanup",
            Self::UserTemp => "cleanup.user_temp",
            Self::BrowserCache => "cleanup.browser_cache",
            Self::CrashReports => "cleanup.crash_reports",
            Self::ScoopCache => "cleanup.scoop_cache",
            Self::NpmCache => "cleanup.npm_cache",
            Self::NpmLogs => "cleanup.npm_logs",
            Self::OllamaModels => "review.ollama_models",
            Self::OllamaBlobs => "protected.ollama_shared_blobs",
        }
    }

    fn tier(self) -> PolicyTier {
        match self {
            Self::GeneratedProjectData
            | Self::RecycleBin
            | Self::WindowsManagedCleanup
            | Self::OllamaModels => PolicyTier::ReviewRequired,
            Self::UserTemp
            | Self::BrowserCache
            | Self::CrashReports
            | Self::ScoopCache
            | Self::NpmCache
            | Self::NpmLogs => PolicyTier::CleanupCandidate,
            _ => PolicyTier::Protected,
        }
    }

    fn action(self) -> PlanActionKind {
        match self {
            Self::ScoopCache => PlanActionKind::RunScoopCache,
            Self::OllamaModels => PlanActionKind::RunOllamaRm,
            Self::InstalledApplication => PlanActionKind::OpenWindowsAppsSettings,
            Self::System | Self::RecycleBin | Self::WindowsManagedCleanup => {
                PlanActionKind::OpenWindowsStorageSettings
            }
            Self::Unknown
            | Self::ScanRoot
            | Self::PersonalData
            | Self::SourceData
            | Self::EncryptedData
            | Self::BackupData
            | Self::UserProtected
            | Self::MixedContent
            | Self::GeneratedProjectData
            | Self::OllamaBlobs => PlanActionKind::OpenLocation,
            Self::UserTemp
            | Self::BrowserCache
            | Self::CrashReports
            | Self::NpmCache
            | Self::NpmLogs => PlanActionKind::Inspect,
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::UserTemp => 0,
            Self::BrowserCache => 1,
            Self::CrashReports => 2,
            Self::ScoopCache => 3,
            Self::NpmCache => 4,
            Self::NpmLogs => 5,
            _ => u8::MAX,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::GeneratedProjectData => "Generated project data",
            Self::RecycleBin => "Recycle Bin contents",
            Self::WindowsManagedCleanup => "Windows-managed cleanup",
            Self::UserTemp => "User temporary files",
            Self::BrowserCache => "Browser caches",
            Self::CrashReports => "Crash reports",
            Self::ScoopCache => "Scoop download cache",
            Self::NpmCache => "npm package cache",
            Self::NpmLogs => "npm diagnostic logs",
            Self::OllamaModels => "Ollama models",
            _ => "Storage item",
        }
    }

    fn evidence(self) -> &'static str {
        match self {
            Self::Unknown => "No reviewed cleanup rule matched this item",
            Self::ScanRoot => "Scan roots cannot be cleanup-plan items",
            Self::System => "Path is inside a protected Windows or shared system root",
            Self::InstalledApplication => "Path is owned by an installed application",
            Self::PersonalData => "File extension is associated with personal content",
            Self::SourceData => "Name or extension identifies source or VCS data",
            Self::EncryptedData => "Filesystem metadata marks this item as encrypted",
            Self::BackupData => "Name or extension identifies backup data",
            Self::UserProtected => "Path matches a persistent user protection",
            Self::MixedContent => "Directory contains content outside one cleanup rule",
            Self::GeneratedProjectData => {
                "Directory is generated project data and may require a rebuild"
            }
            Self::RecycleBin => "Path is inside the Recycle Bin and requires user review",
            Self::WindowsManagedCleanup => "Path is managed by Windows cleanup surfaces",
            Self::UserTemp => "Path is inside the current user's exact temporary-data root",
            Self::BrowserCache => "Path matches a reviewed browser cache component",
            Self::CrashReports => "Path matches the Windows user crash-dump root",
            Self::ScoopCache => "Path is inside Scoop's exact download-cache root",
            Self::NpmCache => "Path matches npm's content-addressed package cache",
            Self::NpmLogs => "Path matches npm's diagnostic-log directory",
            Self::OllamaModels => "Path is Ollama model storage; removal must use ollama rm",
            Self::OllamaBlobs => {
                "Path is shared Ollama blob storage and cannot be deleted directly"
            }
        }
    }
}

#[derive(Debug)]
pub struct AnalyzerIndex {
    coverage: ScanCoverage,
    rules: Vec<Rule>,
    owners: Vec<OwnerRecord>,
    node_owners: Vec<u32>,
    user_protected: Vec<bool>,
    dismissed: HashSet<(String, String)>,
    sort_cache: Mutex<SortCache>,
    volume_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SortCacheKey {
    parent: u32,
    sort: ItemSort,
    direction: SortDirection,
}

#[derive(Debug, Default)]
struct SortCache {
    entries: VecDeque<(SortCacheKey, Arc<[u32]>)>,
    total_indices: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerSettings {
    pub protected_paths: Vec<ProtectedPath>,
    pub dismissed_suggestions: Vec<DismissedSuggestion>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtectedPath {
    Identified {
        volume_id: String,
        relative_path: String,
    },
    Absolute {
        absolute_path: String,
    },
    Legacy(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DismissedSuggestion {
    pub canonical_path: String,
    pub rule_id: String,
}

impl AnalyzerSettings {
    pub fn normalized(mut self) -> Self {
        self.protected_paths = self
            .protected_paths
            .into_iter()
            .filter_map(ProtectedPath::normalized)
            .collect();
        self.protected_paths.sort();
        self.protected_paths.dedup();
        self.dismissed_suggestions = self
            .dismissed_suggestions
            .into_iter()
            .filter_map(|suggestion| {
                let canonical_path = canonical_path(&suggestion.canonical_path);
                let rule_id = suggestion.rule_id.trim().to_owned();
                (!canonical_path.is_empty() && !rule_id.is_empty() && rule_id.len() <= 256)
                    .then_some(DismissedSuggestion {
                        canonical_path,
                        rule_id,
                    })
            })
            .collect();
        self.dismissed_suggestions.sort_by(|left, right| {
            left.canonical_path
                .cmp(&right.canonical_path)
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        self.dismissed_suggestions.dedup();
        self
    }
}

impl ProtectedPath {
    fn normalized(self) -> Option<Self> {
        match self {
            Self::Identified {
                volume_id,
                relative_path,
            } => {
                let volume_id = canonical_volume_id(&volume_id);
                let relative_path = canonical_relative_path(&relative_path);
                (!volume_id.is_empty() && !relative_path.is_empty()).then_some(Self::Identified {
                    volume_id,
                    relative_path,
                })
            }
            Self::Absolute { absolute_path } | Self::Legacy(absolute_path) => {
                let absolute_path = canonical_path(absolute_path);
                (!absolute_path.is_empty()).then_some(Self::Absolute { absolute_path })
            }
        }
    }
}

impl AnalyzerIndex {
    pub fn build(arena: &ScanArena, coverage: ScanCoverage, target: &ScanTarget) -> Self {
        let owners = discover_owners();
        let owner_roots: HashMap<_, _> = owners
            .iter()
            .enumerate()
            .map(|(index, owner)| (owner.canonical_root.clone(), index as u32))
            .collect();
        let mut index = Self {
            coverage,
            rules: vec![Rule::Unknown; arena.node_count()],
            node_owners: vec![NO_OWNER; arena.node_count()],
            user_protected: vec![false; arena.node_count()],
            dismissed: HashSet::new(),
            sort_cache: Mutex::new(SortCache::default()),
            volume_id: target.volume_id.as_deref().map(canonical_volume_id),
            owners,
        };
        if arena.node_count() == 0 {
            return index;
        }

        let mut path = canonical_path(arena.path(0));
        index.rules[0] = Rule::ScanRoot;
        index.node_owners[0] = owner_roots.get(&path).copied().unwrap_or(NO_OWNER);
        let mut stack = vec![WalkFrame {
            next_child: arena.node(0).map_or(NO_INDEX, |node| node.first_child),
            restore_len: 0,
            owner: index.node_owners[0],
            rule: Rule::ScanRoot,
        }];

        while let Some(frame) = stack.last_mut() {
            if frame.next_child == NO_INDEX {
                let restore_len = frame.restore_len;
                stack.pop();
                path.truncate(restore_len);
                continue;
            }
            let child = frame.next_child;
            let Some(node) = arena.node(child) else {
                frame.next_child = NO_INDEX;
                continue;
            };
            frame.next_child = node.next_sibling;
            let parent_owner = frame.owner;
            let parent_rule = frame.rule;
            let restore_len = path.len();
            if !path.ends_with('\\') {
                path.push('\\');
            }
            path.push_str(&arena.name(child).to_lowercase());
            let owner = owner_roots.get(&path).copied().unwrap_or(parent_owner);
            let rule = classify(
                &path,
                arena.name(child),
                node,
                parent_rule,
                owner,
                &index.owners,
            );
            index.rules[child as usize] = rule;
            index.node_owners[child as usize] = owner;
            stack.push(WalkFrame {
                next_child: node.first_child,
                restore_len,
                owner,
                rule,
            });
        }
        index.downgrade_mixed_candidate_directories(arena);
        index
    }

    pub fn apply_settings(&mut self, arena: &ScanArena, settings: &AnalyzerSettings) {
        if let Ok(mut cache) = self.sort_cache.lock() {
            *cache = SortCache::default();
        }
        self.user_protected.fill(false);
        if !settings.protected_paths.is_empty() && arena.node_count() > 0 {
            let mut path = canonical_path(arena.path(0));
            let root_protected = settings
                .protected_paths
                .iter()
                .any(|protected| self.protection_matches(&path, protected));
            self.user_protected[0] = root_protected;
            let mut stack = vec![SettingsFrame {
                next_child: arena.node(0).map_or(NO_INDEX, |node| node.first_child),
                restore_len: 0,
                protected: root_protected,
            }];
            while let Some(frame) = stack.last_mut() {
                if frame.next_child == NO_INDEX {
                    let restore_len = frame.restore_len;
                    stack.pop();
                    path.truncate(restore_len);
                    continue;
                }
                let child = frame.next_child;
                let Some(node) = arena.node(child) else {
                    frame.next_child = NO_INDEX;
                    continue;
                };
                frame.next_child = node.next_sibling;
                let parent_protected = frame.protected;
                let restore_len = path.len();
                if !path.ends_with('\\') {
                    path.push('\\');
                }
                path.push_str(&arena.name(child).to_lowercase());
                let protected = parent_protected
                    || settings
                        .protected_paths
                        .iter()
                        .any(|root| self.protection_matches(&path, root));
                self.user_protected[child as usize] = protected;
                stack.push(SettingsFrame {
                    next_child: node.first_child,
                    restore_len,
                    protected,
                });
            }
        }
        self.dismissed = settings
            .dismissed_suggestions
            .iter()
            .map(|suggestion| {
                (
                    suggestion.canonical_path.clone(),
                    suggestion.rule_id.clone(),
                )
            })
            .collect();
    }

    pub fn estimated_memory_bytes(&self) -> u64 {
        let fixed = self
            .rules
            .capacity()
            .saturating_mul(std::mem::size_of::<Rule>())
            .saturating_add(
                self.node_owners
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(
                self.user_protected
                    .capacity()
                    .saturating_mul(std::mem::size_of::<bool>()),
            );
        let cached = self.sort_cache.lock().map_or(0, |cache| {
            cache
                .total_indices
                .saturating_mul(std::mem::size_of::<u32>())
        });
        u64::try_from(fixed.saturating_add(cached)).unwrap_or(u64::MAX)
    }

    pub fn protection_key(
        &self,
        arena: &ScanArena,
        node_id: &str,
    ) -> Result<ProtectedPath, ScanFailure> {
        let index = arena.parse_node_id(node_id)?;
        let path = canonical_path(arena.path(index));
        if let Some(volume_id) = &self.volume_id
            && let Some(relative_path) = volume_relative_path(&path)
        {
            return Ok(ProtectedPath::Identified {
                volume_id: volume_id.clone(),
                relative_path,
            });
        }
        Ok(ProtectedPath::Absolute {
            absolute_path: path,
        })
    }

    fn protection_matches(&self, path: &str, protected: &ProtectedPath) -> bool {
        match protected {
            ProtectedPath::Identified {
                volume_id,
                relative_path,
            } => {
                self.volume_id
                    .as_ref()
                    .is_some_and(|current| current == &canonical_volume_id(volume_id))
                    && volume_relative_path(path)
                        .is_some_and(|current| is_same_or_descendant(&current, relative_path))
            }
            ProtectedPath::Absolute { absolute_path } | ProtectedPath::Legacy(absolute_path) => {
                is_same_or_descendant(path, &canonical_path(absolute_path))
            }
        }
    }

    pub fn dismissal_key(
        &self,
        arena: &ScanArena,
        request: &DismissSuggestionRequest,
    ) -> Result<DismissedSuggestion, ScanFailure> {
        let index = arena.parse_node_id(&request.node_id)?;
        let rule = self.effective_rule(index);
        if rule.id() != request.rule_id {
            return Err(ScanFailure::new(
                "POLICY_RULE_CHANGED",
                "The suggestion rule no longer matches this item",
                true,
            ));
        }
        Ok(DismissedSuggestion {
            canonical_path: canonical_path(arena.path(index)),
            rule_id: request.rule_id.clone(),
        })
    }

    pub fn query(&self, arena: &ScanArena, query: &ItemQuery) -> Result<ItemPage, ScanFailure> {
        self.query_cancellable(arena, query, &AtomicBool::new(false))
    }

    pub fn query_cancellable(
        &self,
        arena: &ScanArena,
        query: &ItemQuery,
        cancel: &AtomicBool,
    ) -> Result<ItemPage, ScanFailure> {
        let scope = query
            .scope_id
            .as_deref()
            .or(query.parent_id.as_deref())
            .map(|id| arena.parse_node_id(id))
            .transpose()?
            .unwrap_or(0);
        validate_decimal_filter(query.min_bytes.as_deref(), "min_bytes")?;
        validate_decimal_filter(query.modified_before_ms.as_deref(), "modified_before_ms")?;
        validate_query_id(query.query_id.as_deref())?;
        let recursive = query
            .text
            .as_ref()
            .is_some_and(|text| !text.trim().is_empty())
            || query.kinds.is_some()
            || query.extensions.is_some()
            || query.policy_tiers.is_some()
            || query.owner_ids.is_some()
            || query.min_bytes.is_some()
            || query.modified_before_ms.is_some();
        let signature = query_fingerprint(query, scope);
        let candidates = if recursive {
            let mut candidates = Vec::new();
            visit_descendants(arena, scope, cancel, |index| {
                if self.matches(arena, index, query) {
                    candidates.push(index);
                }
            })?;
            ensure_query_active(cancel)?;
            candidates.sort_unstable_by(|left, right| {
                let ordering = self.compare(arena, *left, *right, query.sort);
                let ordering = match query.direction {
                    SortDirection::Asc => ordering,
                    SortDirection::Desc => ordering.reverse(),
                };
                ordering.then_with(|| left.cmp(right))
            });
            Arc::<[u32]>::from(candidates)
        } else {
            self.sorted_children(arena, scope, query.sort, query.direction)?
        };
        ensure_query_active(cancel)?;

        let start = query
            .cursor
            .as_deref()
            .map(|cursor| parse_query_cursor(arena, cursor, signature))
            .transpose()?
            .unwrap_or(0);
        if start > candidates.len() {
            return Err(ScanFailure::new(
                "INVALID_CURSOR",
                "The query cursor is outside the result set",
                true,
            ));
        }
        let limit = usize::from(query.limit.clamp(1, 100));
        let end = start.saturating_add(limit).min(candidates.len());
        let items = candidates[start..end]
            .iter()
            .map(|index| self.item_row(arena, *index))
            .collect();
        let next_cursor = (end < candidates.len()).then(|| query_cursor(arena, signature, end));
        Ok(ItemPage { items, next_cursor })
    }

    fn sorted_children(
        &self,
        arena: &ScanArena,
        parent: u32,
        sort: ItemSort,
        direction: SortDirection,
    ) -> Result<Arc<[u32]>, ScanFailure> {
        let key = SortCacheKey {
            parent,
            sort,
            direction,
        };
        if let Ok(mut cache) = self.sort_cache.lock()
            && let Some(position) = cache
                .entries
                .iter()
                .position(|(candidate, _)| *candidate == key)
        {
            let entry = cache.entries.remove(position).expect("cache entry exists");
            let result = Arc::clone(&entry.1);
            cache.entries.push_back(entry);
            return Ok(result);
        }

        let mut children = arena.child_indices(parent)?;
        children.sort_unstable_by(|left, right| {
            let ordering = self.compare(arena, *left, *right, sort);
            let ordering = match direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            };
            ordering.then_with(|| left.cmp(right))
        });
        let result = Arc::<[u32]>::from(children);
        if result.len() <= MAX_CACHED_SORT_INDICES
            && let Ok(mut cache) = self.sort_cache.lock()
        {
            while cache.total_indices.saturating_add(result.len()) > MAX_CACHED_SORT_INDICES {
                let Some((_, evicted)) = cache.entries.pop_front() else {
                    break;
                };
                cache.total_indices = cache.total_indices.saturating_sub(evicted.len());
            }
            cache.total_indices = cache.total_indices.saturating_add(result.len());
            cache.entries.push_back((key, Arc::clone(&result)));
        }
        Ok(result)
    }

    pub fn item_details(
        &self,
        arena: &ScanArena,
        node_id: &str,
    ) -> Result<ItemDetails, ScanFailure> {
        let index = arena.parse_node_id(node_id)?;
        let item = self.item_row(arena, index);
        Ok(ItemDetails {
            evidence: item.policy.clone(),
            item,
        })
    }

    pub fn aggregate(
        &self,
        arena: &ScanArena,
        query: &StorageAggregateQuery,
    ) -> Result<StorageAggregate, ScanFailure> {
        let scope = query
            .scope_id
            .as_deref()
            .map(|id| arena.parse_node_id(id))
            .transpose()?
            .unwrap_or(0);
        let mut buckets = BTreeMap::<Cow<'_, str>, BucketAccumulator>::new();
        let mut add = |index| {
            let Some(node) = arena.node(index) else {
                return;
            };
            let (key, label) = self.aggregate_key(arena, index, query.dimension);
            let bucket = buckets.entry(key).or_insert_with(|| BucketAccumulator {
                label: label.into_owned(),
                ..BucketAccumulator::default()
            });
            bucket.items = bucket.items.saturating_add(1);
            bucket.logical = bucket.logical.saturating_add(node.logical_bytes);
            bucket.allocated = bucket.allocated.saturating_add(node.allocated_bytes);
        };
        if query.dimension == AggregateDimension::Kind {
            for index in arena.child_indices(scope)? {
                add(index);
            }
        } else {
            visit_descendants(arena, scope, &AtomicBool::new(false), |index| {
                if arena.node(index).is_some_and(|node| !node.is_directory()) {
                    add(index);
                }
            })?;
        }
        let mut buckets: Vec<_> = buckets.into_iter().collect();
        buckets.sort_unstable_by(|left, right| {
            right
                .1
                .allocated
                .cmp(&left.1.allocated)
                .then_with(|| left.0.cmp(&right.0))
        });
        let limit = usize::from(query.limit.clamp(1, 100));
        let remainder = buckets.split_off(limit.min(buckets.len()));
        let other =
            remainder
                .into_iter()
                .fold(BucketAccumulator::default(), |mut total, (_, bucket)| {
                    total.items = total.items.saturating_add(bucket.items);
                    total.logical = total.logical.saturating_add(bucket.logical);
                    total.allocated = total.allocated.saturating_add(bucket.allocated);
                    total
                });
        Ok(StorageAggregate {
            buckets: buckets
                .into_iter()
                .map(|(key, bucket)| StorageBucket {
                    key: key.into_owned(),
                    label: bucket.label,
                    item_count: bucket.items.to_string(),
                    logical_bytes: bucket.logical.to_string(),
                    allocated_bytes: bucket.allocated.to_string(),
                })
                .collect(),
            other_item_count: other.items.to_string(),
            other_logical_bytes: other.logical.to_string(),
            other_allocated_bytes: other.allocated.to_string(),
        })
    }

    pub fn treemap(
        &self,
        arena: &ScanArena,
        query: &TreemapQuery,
    ) -> Result<TreemapSlice, ScanFailure> {
        let scope = query
            .scope_id
            .as_deref()
            .map(|id| arena.parse_node_id(id))
            .transpose()?
            .unwrap_or(0);
        let children =
            self.sorted_children(arena, scope, ItemSort::Allocated, SortDirection::Desc)?;
        let limit = usize::from(query.max_nodes.clamp(1, 5_000));
        let visible = limit.min(children.len());
        let hidden = &children[visible..];
        let other_allocated = hidden.iter().fold(0u64, |total, index| {
            total.saturating_add(arena.node(*index).map_or(0, |node| node.allocated_bytes))
        });
        let mut nodes: Vec<_> = children[..visible]
            .iter()
            .map(|index| self.treemap_node(arena, *index, Some(scope)))
            .collect();
        if other_allocated > 0 {
            nodes.push(TreemapNode {
                id: format!("{}:other:{scope}", arena.session_id()),
                parent_id: Some(arena.node_id(scope)),
                name: "Other".to_owned(),
                allocated_bytes: other_allocated.to_string(),
                kind: ItemKind::Directory,
                policy_tier: PolicyTier::Protected,
                owner_id: None,
                synthetic: true,
            });
        }
        Ok(TreemapSlice {
            nodes,
            truncated: visible < children.len(),
            other_allocated_bytes: other_allocated.to_string(),
        })
    }

    pub fn build_plan(
        &self,
        arena: &ScanArena,
        request: &CleanupPlanRequest,
    ) -> Result<CleanupPlan, ScanFailure> {
        let target = request
            .target_bytes
            .as_deref()
            .map(|value| parse_decimal(value, "target_bytes"))
            .transpose()?;
        let uniform_candidates = self.uniform_candidate_rules(arena);
        let mut opportunities = Vec::<PlanOpportunity>::new();
        for index in 1..arena.node_count() as u32 {
            let rule = self.effective_rule(index);
            let tier = self.effective_tier(index);
            if tier == PolicyTier::Protected || self.coverage != ScanCoverage::Complete {
                continue;
            }
            let Some(node) = arena.node(index) else {
                continue;
            };
            if node.allocated_bytes == 0 {
                continue;
            }
            if tier == PolicyTier::CleanupCandidate {
                if uniform_candidates[index as usize] != Some(rule)
                    || arena.node(index).is_some_and(|node| {
                        node.parent != NO_INDEX
                            && uniform_candidates[node.parent as usize] == Some(rule)
                    })
                {
                    continue;
                }
            } else if self.same_opportunity_as_parent(arena, index, rule) {
                continue;
            }
            let canonical = canonical_path(arena.path(index));
            if self.dismissed.contains(&(canonical, rule.id().to_owned())) {
                continue;
            }
            let owner = self.node_owners[index as usize];
            opportunities.push(PlanOpportunity {
                index,
                rule,
                owner,
                bytes: node.allocated_bytes,
            });
        }
        opportunities.sort_unstable_by(|left, right| {
            plan_tier_rank(left.rule.tier())
                .cmp(&plan_tier_rank(right.rule.tier()))
                .then_with(|| left.rule.priority().cmp(&right.rule.priority()))
                .then_with(|| right.bytes.cmp(&left.bytes))
                .then_with(|| left.rule.cmp(&right.rule))
                .then_with(|| left.owner.cmp(&right.owner))
                .then_with(|| left.index.cmp(&right.index))
        });

        let mut selected_candidate = 0u64;
        let mut review_potential = 0u64;
        let mut items = Vec::with_capacity(opportunities.len());
        let mut omitted_items = 0u64;
        let mut omitted_candidates = 0u64;
        let mut omitted_review = 0u64;
        for opportunity in opportunities {
            let rule = opportunity.rule;
            let tier = rule.tier();
            if items.len() >= MAX_PLAN_ITEMS {
                omitted_items = omitted_items.saturating_add(1);
                if tier == PolicyTier::CleanupCandidate {
                    omitted_candidates = omitted_candidates.saturating_add(opportunity.bytes);
                } else if tier == PolicyTier::ReviewRequired {
                    omitted_review = omitted_review.saturating_add(opportunity.bytes);
                }
                continue;
            }
            let selected = tier == PolicyTier::CleanupCandidate
                && target.is_none_or(|target| selected_candidate < target);
            if selected {
                selected_candidate = selected_candidate.saturating_add(opportunity.bytes);
            }
            if tier == PolicyTier::ReviewRequired {
                review_potential = review_potential.saturating_add(opportunity.bytes);
            }
            let evidence = vec![self.policy_evidence(arena, opportunity.index)];
            items.push(PlanItem {
                id: format!("{}:plan:{}", arena.session_id(), items.len()),
                node_ids: vec![arena.node_id(opportunity.index)],
                title: format!("{}: {}", rule.title(), arena.name(opportunity.index)),
                category: rule.id().to_owned(),
                tier,
                selected,
                reclaimable_bytes: opportunity.bytes.to_string(),
                evidence,
                warnings: coverage_warnings(self.coverage),
                action_kind: rule.action(),
            });
        }
        Ok(CleanupPlan {
            session_id: arena.session_id().to_owned(),
            target_bytes: target.map(|value| value.to_string()),
            selected_candidate_bytes: selected_candidate.to_string(),
            selected_review_bytes: "0".to_owned(),
            review_potential_bytes: review_potential.to_string(),
            target_shortfall_bytes: target
                .map_or(0, |target| target.saturating_sub(selected_candidate))
                .to_string(),
            truncated: omitted_items > 0,
            omitted_item_count: omitted_items.to_string(),
            omitted_candidate_bytes: omitted_candidates.to_string(),
            omitted_review_bytes: omitted_review.to_string(),
            items,
        })
    }

    pub fn edit_plan(
        &self,
        arena: &ScanArena,
        plan: &mut CleanupPlan,
        edit: &PlanEdit,
    ) -> Result<(), ScanFailure> {
        if plan.session_id != arena.session_id() {
            return Err(stale_session());
        }
        let item = plan
            .items
            .iter_mut()
            .find(|item| item.id == edit.item_id)
            .ok_or_else(|| {
                ScanFailure::new("INVALID_PLAN_ITEM", "Plan item was not found", true)
            })?;
        for node_id in &item.node_ids {
            let index = arena.parse_node_id(node_id)?;
            if self.effective_tier(index) != item.tier {
                return Err(ScanFailure::new(
                    "PLAN_ITEM_CHANGED",
                    "The item policy changed; rebuild the cleanup plan",
                    true,
                ));
            }
        }
        item.selected = edit.selected;
        recompute_plan_totals(plan)?;
        Ok(())
    }

    pub fn set_path_protection(
        &mut self,
        arena: &ScanArena,
        request: &PathProtectionRequest,
    ) -> Result<PolicyEvidence, ScanFailure> {
        let root = arena.parse_node_id(&request.node_id)?;
        self.user_protected[root as usize] = request.protected;
        for index in descendants(arena, root) {
            self.user_protected[index as usize] = request.protected;
        }
        Ok(self.policy_evidence(arena, root))
    }

    pub fn dismiss_suggestion(
        &mut self,
        arena: &ScanArena,
        request: &DismissSuggestionRequest,
    ) -> Result<bool, ScanFailure> {
        let index = arena.parse_node_id(&request.node_id)?;
        let rule = self.effective_rule(index);
        if rule.id() != request.rule_id {
            return Err(ScanFailure::new(
                "POLICY_RULE_CHANGED",
                "The suggestion rule no longer matches this item",
                true,
            ));
        }
        let key = (canonical_path(arena.path(index)), request.rule_id.clone());
        if request.dismissed {
            self.dismissed.insert(key);
        } else {
            self.dismissed.remove(&key);
        }
        Ok(request.dismissed)
    }

    fn item_row(&self, arena: &ScanArena, index: u32) -> ItemRow {
        let mut row = arena.item_row(index);
        row.owner = self.owner_summary(arena, index);
        row.policy = self.policy_evidence(arena, index);
        row
    }

    fn owner_summary(&self, arena: &ScanArena, index: u32) -> Option<OwnerSummary> {
        let owner_index = *self.node_owners.get(index as usize)?;
        let owner = self.owners.get(owner_index as usize)?;
        let mut summary = owner.summary.clone();
        if canonical_path(arena.path(index)) == owner.canonical_root {
            summary.match_kind = OwnerMatchKind::Exact;
        }
        Some(summary)
    }

    fn policy_evidence(&self, arena: &ScanArena, index: u32) -> PolicyEvidence {
        let rule = self.effective_rule(index);
        let tier = self.effective_tier(index);
        let mut facts = vec![
            format!("Matched bundled policy rule {}", rule.id()),
            rule.evidence().to_owned(),
        ];
        if let Some(node) = arena.node(index) {
            facts.push(format!("Allocated bytes: {}", node.allocated_bytes));
            if node.is_sparse() {
                facts.push("Filesystem metadata marks this item as sparse".to_owned());
            }
            if node.is_compressed() {
                facts.push("Filesystem metadata marks this item as compressed".to_owned());
            }
            if node.has_named_stream() {
                facts.push("Allocated and logical totals include named data streams".to_owned());
            }
            if node.is_encrypted() {
                facts.push("Filesystem metadata marks this item as encrypted".to_owned());
            }
            if node.is_reparse_point() {
                facts.push("Reparse target was not traversed".to_owned());
            }
            if node.is_inaccessible() {
                facts.push("Scanner could not enumerate this item's contents".to_owned());
            }
        }
        let mut inference = Vec::new();
        if let Some(owner) = self.owner_summary(arena, index) {
            let statement = format!("Storage owner: {} ({:?})", owner.name, owner.source);
            if owner.match_kind == OwnerMatchKind::Exact {
                facts.push(statement);
            } else {
                inference.push(statement);
            }
        }
        PolicyEvidence {
            tier,
            rule_id: rule.id().to_owned(),
            rule_version: RULE_VERSION.to_owned(),
            facts,
            inference,
            warnings: coverage_warnings(self.coverage),
        }
    }

    fn effective_rule(&self, index: u32) -> Rule {
        if self
            .user_protected
            .get(index as usize)
            .copied()
            .unwrap_or(false)
        {
            Rule::UserProtected
        } else {
            self.rules
                .get(index as usize)
                .copied()
                .unwrap_or(Rule::Unknown)
        }
    }

    fn effective_tier(&self, index: u32) -> PolicyTier {
        let tier = self.effective_rule(index).tier();
        if tier == PolicyTier::CleanupCandidate && self.coverage != ScanCoverage::Complete {
            PolicyTier::ReviewRequired
        } else {
            tier
        }
    }

    fn matches(&self, arena: &ScanArena, index: u32, query: &ItemQuery) -> bool {
        let Some(node) = arena.node(index) else {
            return false;
        };
        if let Some(text) = query
            .text
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            && !contains_case_insensitive(arena.name(index), text)
        {
            return false;
        }
        if query
            .kinds
            .as_ref()
            .is_some_and(|kinds| !kinds.contains(&item_kind(node)))
        {
            return false;
        }
        if let Some(extensions) = &query.extensions {
            let extension = extension_slice(arena.name(index));
            if !extensions.iter().any(|candidate| {
                extension.is_some_and(|value| value.eq_ignore_ascii_case(candidate))
            }) {
                return false;
            }
        }
        if query
            .policy_tiers
            .as_ref()
            .is_some_and(|tiers| !tiers.contains(&self.effective_tier(index)))
        {
            return false;
        }
        if let Some(owner_ids) = &query.owner_ids {
            let owner_id = self
                .owners
                .get(self.node_owners[index as usize] as usize)
                .map(|owner| owner.summary.id.as_str());
            if !owner_ids
                .iter()
                .any(|candidate| Some(candidate.as_str()) == owner_id)
            {
                return false;
            }
        }
        if let Some(minimum) = query
            .min_bytes
            .as_deref()
            .and_then(|value| value.parse().ok())
            && node.allocated_bytes < minimum
        {
            return false;
        }
        if let Some(before) = query
            .modified_before_ms
            .as_deref()
            .and_then(|value| value.parse::<i64>().ok())
            && (node.modified_at_ms < 0 || node.modified_at_ms >= before)
        {
            return false;
        }
        true
    }

    fn compare(&self, arena: &ScanArena, left: u32, right: u32, sort: ItemSort) -> Ordering {
        let left_node = arena.node(left).expect("query index is valid");
        let right_node = arena.node(right).expect("query index is valid");
        match sort {
            ItemSort::Name => arena.name(left).cmp(arena.name(right)),
            ItemSort::Allocated => left_node.allocated_bytes.cmp(&right_node.allocated_bytes),
            ItemSort::Logical => left_node.logical_bytes.cmp(&right_node.logical_bytes),
            ItemSort::Modified => left_node.modified_at_ms.cmp(&right_node.modified_at_ms),
            ItemSort::Type => item_kind(left_node).cmp(&item_kind(right_node)),
            ItemSort::Policy => self.effective_tier(left).cmp(&self.effective_tier(right)),
            ItemSort::Owner => self
                .owners
                .get(self.node_owners[left as usize] as usize)
                .map(|owner| owner.summary.name.as_str())
                .cmp(
                    &self
                        .owners
                        .get(self.node_owners[right as usize] as usize)
                        .map(|owner| owner.summary.name.as_str()),
                ),
        }
    }

    fn aggregate_key<'a>(
        &'a self,
        arena: &'a ScanArena,
        index: u32,
        dimension: AggregateDimension,
    ) -> (Cow<'a, str>, Cow<'a, str>) {
        match dimension {
            AggregateDimension::Extension => extension_slice(arena.name(index))
                .map(|extension| {
                    let extension = if extension.bytes().any(|byte| byte.is_ascii_uppercase()) {
                        Cow::Owned(extension.to_ascii_lowercase())
                    } else {
                        Cow::Borrowed(extension)
                    };
                    (extension.clone(), extension)
                })
                .unwrap_or_else(|| (Cow::Borrowed("(none)"), Cow::Borrowed("No extension"))),
            AggregateDimension::Owner => self
                .owners
                .get(self.node_owners[index as usize] as usize)
                .map(|owner| {
                    (
                        Cow::Borrowed(owner.summary.id.as_str()),
                        Cow::Borrowed(owner.summary.name.as_str()),
                    )
                })
                .unwrap_or_else(|| (Cow::Borrowed("unknown"), Cow::Borrowed("Unknown owner"))),
            AggregateDimension::Policy => {
                let tier = self.effective_tier(index);
                match tier {
                    PolicyTier::Protected => {
                        (Cow::Borrowed("protected"), Cow::Borrowed("Protected"))
                    }
                    PolicyTier::ReviewRequired => (
                        Cow::Borrowed("review_required"),
                        Cow::Borrowed("Review required"),
                    ),
                    PolicyTier::CleanupCandidate => (
                        Cow::Borrowed("cleanup_candidate"),
                        Cow::Borrowed("Cleanup candidate"),
                    ),
                }
            }
            AggregateDimension::Kind => {
                let kind = arena.node(index).map_or(ItemKind::File, item_kind);
                match kind {
                    ItemKind::File => (Cow::Borrowed("file"), Cow::Borrowed("File")),
                    ItemKind::Directory => (Cow::Borrowed("directory"), Cow::Borrowed("Directory")),
                    ItemKind::ReparsePoint => (
                        Cow::Borrowed("reparse_point"),
                        Cow::Borrowed("Reparse point"),
                    ),
                }
            }
        }
    }

    fn treemap_node(&self, arena: &ScanArena, index: u32, parent: Option<u32>) -> TreemapNode {
        let node = arena.node(index).expect("treemap index is valid");
        TreemapNode {
            id: arena.node_id(index),
            parent_id: parent.map(|parent| arena.node_id(parent)),
            name: arena.name(index).to_owned(),
            allocated_bytes: node.allocated_bytes.to_string(),
            kind: item_kind(node),
            policy_tier: self.effective_tier(index),
            owner_id: self
                .owners
                .get(self.node_owners[index as usize] as usize)
                .map(|owner| owner.summary.id.clone()),
            synthetic: false,
        }
    }

    fn same_opportunity_as_parent(&self, arena: &ScanArena, index: u32, rule: Rule) -> bool {
        arena
            .node(index)
            .filter(|node| node.parent != NO_INDEX)
            .is_some_and(|node| self.effective_rule(node.parent) == rule)
    }

    fn downgrade_mixed_candidate_directories(&mut self, arena: &ScanArena) {
        let mut order = vec![0];
        order.extend(descendants(arena, 0));
        for index in order.into_iter().rev() {
            let rule = self.rules[index as usize];
            if rule.tier() != PolicyTier::CleanupCandidate
                || !arena.node(index).is_some_and(ArenaNode::is_directory)
            {
                continue;
            }
            let mut child = arena.node(index).map_or(NO_INDEX, |node| node.first_child);
            while child != NO_INDEX {
                if self.rules[child as usize] != rule {
                    self.rules[index as usize] = Rule::MixedContent;
                    break;
                }
                child = arena.node(child).map_or(NO_INDEX, |node| node.next_sibling);
            }
        }
    }

    fn uniform_candidate_rules(&self, arena: &ScanArena) -> Vec<Option<Rule>> {
        let mut uniform = vec![None; arena.node_count()];
        let mut order = vec![0];
        order.extend(descendants(arena, 0));
        for index in order.into_iter().rev() {
            let rule = self.effective_rule(index);
            if self.effective_tier(index) != PolicyTier::CleanupCandidate {
                continue;
            }
            let mut child = arena.node(index).map_or(NO_INDEX, |node| node.first_child);
            let mut children_match = true;
            while child != NO_INDEX {
                if uniform[child as usize] != Some(rule) {
                    children_match = false;
                    break;
                }
                child = arena.node(child).map_or(NO_INDEX, |node| node.next_sibling);
            }
            if children_match {
                uniform[index as usize] = Some(rule);
            }
        }
        uniform
    }
}

fn classify(
    path: &str,
    name: &str,
    node: &ArenaNode,
    parent_rule: Rule,
    owner: u32,
    owners: &[OwnerRecord],
) -> Rule {
    let name = name.to_lowercase();
    let extension = extension_slice(&name);
    if is_personal_extension(extension) {
        return Rule::PersonalData;
    }
    if is_source_name(&name) || is_source_extension(extension) {
        return Rule::SourceData;
    }
    if node.is_encrypted() {
        return Rule::EncryptedData;
    }
    if is_backup_name(&name, extension) {
        return Rule::BackupData;
    }
    if node.is_reparse_point() || node.is_inaccessible() {
        return Rule::Unknown;
    }
    if let Some(owner) = owners
        .get(owner as usize)
        .filter(|owner| owner.summary.id == "ollama-models")
    {
        let relative = path.strip_prefix(&owner.canonical_root).unwrap_or_default();
        return if relative == "\\blobs" || relative.starts_with("\\blobs\\") {
            Rule::OllamaBlobs
        } else {
            Rule::OllamaModels
        };
    }
    if contains_subtree(path, "\\.ollama\\models\\blobs") {
        return Rule::OllamaBlobs;
    }
    if contains_subtree(path, "\\.ollama\\models") {
        return Rule::OllamaModels;
    }
    if contains_subtree(path, "\\$recycle.bin") {
        return Rule::RecycleBin;
    }
    if is_windows_managed_cleanup(path) {
        return Rule::WindowsManagedCleanup;
    }
    if parent_rule == Rule::System || is_system_path(path) {
        return Rule::System;
    }
    if contains_subtree(path, "\\appdata\\local\\crashdumps") {
        return Rule::CrashReports;
    }
    if contains_subtree(path, "\\appdata\\local\\temp") {
        return Rule::UserTemp;
    }
    if is_browser_cache(path) {
        return Rule::BrowserCache;
    }
    if is_npm_cache(path) {
        return Rule::NpmCache;
    }
    if is_npm_logs(path) {
        return Rule::NpmLogs;
    }
    if let Some(owner) = owners
        .get(owner as usize)
        .filter(|owner| owner.summary.id == "scoop")
    {
        let relative = path.strip_prefix(&owner.canonical_root).unwrap_or_default();
        if relative == "\\cache" || relative.starts_with("\\cache\\") {
            return Rule::ScoopCache;
        }
    }
    if parent_rule == Rule::InstalledApplication || owner != NO_OWNER {
        return Rule::InstalledApplication;
    }
    if is_generated_component(&name) || parent_rule == Rule::GeneratedProjectData {
        return Rule::GeneratedProjectData;
    }
    Rule::Unknown
}

fn is_system_path(path: &str) -> bool {
    contains_subtree(path, "\\windows")
        || contains_subtree(path, "\\program files")
        || contains_subtree(path, "\\programdata")
        || contains_subtree(path, "\\system volume information")
}

fn is_generated_component(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | "target" | ".venv" | "venv" | "__pycache__" | "dist" | "build"
    )
}

fn is_source_name(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | "cargo.toml" | "package.json"
    )
}

fn is_personal_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        matches!(
            extension,
            "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "ppt"
                | "pptx"
                | "pdf"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "webp"
                | "heic"
                | "mp3"
                | "wav"
                | "flac"
                | "mp4"
                | "mov"
                | "mkv"
                | "avi"
        )
    })
}

fn is_source_extension(extension: Option<&str>) -> bool {
    extension.is_some_and(|extension| {
        matches!(
            extension,
            "rs" | "ts"
                | "tsx"
                | "js"
                | "jsx"
                | "py"
                | "go"
                | "java"
                | "kt"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "cs"
                | "swift"
                | "rb"
                | "php"
                | "vue"
                | "svelte"
        )
    })
}

fn is_backup_name(name: &str, extension: Option<&str>) -> bool {
    matches!(name, "backup" | "backups" | "windows.old")
        || extension.is_some_and(|extension| {
            matches!(
                extension,
                "bak" | "backup" | "bkf" | "vhd" | "vhdx" | "vmdk" | "qcow2"
            )
        })
}

fn is_windows_managed_cleanup(path: &str) -> bool {
    contains_subtree(path, "\\microsoft\\windows\\wer\\reportarchive")
        || contains_subtree(path, "\\microsoft\\windows\\wer\\reportqueue")
}

fn is_browser_cache(path: &str) -> bool {
    (contains_subtree(path, "\\google\\chrome\\user data")
        || contains_subtree(path, "\\microsoft\\edge\\user data")
        || contains_subtree(path, "\\mozilla\\firefox\\profiles"))
        && ["cache", "cache_data", "code cache", "gpucache"]
            .iter()
            .any(|component| has_component(path, component))
}

fn is_npm_cache(path: &str) -> bool {
    (contains_subtree(path, "\\appdata\\local\\npm-cache")
        || contains_subtree(path, "\\appdata\\roaming\\npm-cache"))
        && has_component(path, "_cacache")
}

fn is_npm_logs(path: &str) -> bool {
    (contains_subtree(path, "\\appdata\\local\\npm-cache")
        || contains_subtree(path, "\\appdata\\roaming\\npm-cache"))
        && has_component(path, "_logs")
}

fn contains_subtree(path: &str, marker: &str) -> bool {
    path.match_indices(marker).any(|(start, _)| {
        let end = start + marker.len();
        end == path.len() || path.as_bytes().get(end) == Some(&b'\\')
    })
}

fn is_same_or_descendant(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn canonical_volume_id(volume_id: &str) -> String {
    volume_id.trim().replace('/', "\\").to_lowercase()
}

fn canonical_relative_path(path: &str) -> String {
    let mut path = path.trim().replace('/', "\\").to_lowercase();
    if !path.starts_with('\\') {
        path.insert(0, '\\');
    }
    while path.len() > 1 && path.ends_with('\\') {
        path.pop();
    }
    path
}

fn volume_relative_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    Some(canonical_relative_path(path.get(2..).unwrap_or("\\")))
}

fn has_component(path: &str, component: &str) -> bool {
    path.split('\\').any(|part| part == component)
}

fn plan_tier_rank(tier: PolicyTier) -> u8 {
    match tier {
        PolicyTier::CleanupCandidate => 0,
        PolicyTier::ReviewRequired => 1,
        PolicyTier::Protected => 2,
    }
}

fn extension_slice(name: &str) -> Option<&str> {
    name.rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(_, extension)| extension)
}

fn contains_case_insensitive(value: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if value.is_ascii() && needle.is_ascii() {
        return value
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()));
    }
    value.to_lowercase().contains(&needle.to_lowercase())
}

fn item_kind(node: &ArenaNode) -> ItemKind {
    if node.is_reparse_point() {
        ItemKind::ReparsePoint
    } else if node.is_directory() {
        ItemKind::Directory
    } else {
        ItemKind::File
    }
}

fn descendants(arena: &ScanArena, root: u32) -> Vec<u32> {
    let mut result = Vec::new();
    let mut stack = Vec::new();
    if let Some(root) = arena.node(root) {
        let mut child = root.first_child;
        while child != NO_INDEX {
            stack.push(child);
            child = arena.node(child).map_or(NO_INDEX, |node| node.next_sibling);
        }
    }
    while let Some(index) = stack.pop() {
        result.push(index);
        let mut child = arena.node(index).map_or(NO_INDEX, |node| node.first_child);
        while child != NO_INDEX {
            stack.push(child);
            child = arena.node(child).map_or(NO_INDEX, |node| node.next_sibling);
        }
    }
    result
}

fn visit_descendants(
    arena: &ScanArena,
    root: u32,
    cancel: &AtomicBool,
    mut visit: impl FnMut(u32),
) -> Result<(), ScanFailure> {
    let mut stack = Vec::new();
    if let Some(root) = arena.node(root) {
        let mut child = root.first_child;
        while child != NO_INDEX {
            stack.push(child);
            child = arena.node(child).map_or(NO_INDEX, |node| node.next_sibling);
        }
    }
    let mut visited = 0usize;
    while let Some(index) = stack.pop() {
        if visited & 0x3ff == 0 {
            ensure_query_active(cancel)?;
        }
        visit(index);
        visited = visited.saturating_add(1);
        let mut child = arena.node(index).map_or(NO_INDEX, |node| node.first_child);
        while child != NO_INDEX {
            stack.push(child);
            child = arena.node(child).map_or(NO_INDEX, |node| node.next_sibling);
        }
    }
    ensure_query_active(cancel)
}

fn ensure_query_active(cancel: &AtomicBool) -> Result<(), ScanFailure> {
    if cancel.load(AtomicOrdering::Acquire) {
        Err(ScanFailure::new(
            "QUERY_CANCELLED",
            "The analyzer query was cancelled",
            true,
        ))
    } else {
        Ok(())
    }
}

fn validate_query_id(query_id: Option<&str>) -> Result<(), ScanFailure> {
    if query_id.is_some_and(|value| {
        value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) {
        return Err(ScanFailure::new(
            "INVALID_QUERY",
            "query_id must contain 1-128 ASCII letters, digits, dashes, or underscores",
            true,
        ));
    }
    Ok(())
}

fn query_cursor(arena: &ScanArena, signature: u64, offset: usize) -> String {
    format!("{}:q:{signature:016x}:{offset}", arena.session_id())
}

fn parse_query_cursor(
    arena: &ScanArena,
    cursor: &str,
    expected_signature: u64,
) -> Result<usize, ScanFailure> {
    let prefix = format!("{}:q:", arena.session_id());
    let value = cursor.strip_prefix(&prefix).ok_or_else(stale_session)?;
    let (signature, offset) = value.split_once(':').ok_or_else(invalid_cursor)?;
    let signature = u64::from_str_radix(signature, 16).map_err(|_| invalid_cursor())?;
    if signature != expected_signature {
        return Err(ScanFailure::new(
            "INVALID_CURSOR",
            "The query cursor belongs to different filters or sorting",
            true,
        ));
    }
    offset.parse().map_err(|_| invalid_cursor())
}

fn invalid_cursor() -> ScanFailure {
    ScanFailure::new("INVALID_CURSOR", "The query cursor is malformed", true)
}

fn query_fingerprint(query: &ItemQuery, scope: u32) -> u64 {
    let mut fingerprint = Fingerprint::default();
    fingerprint.u64(u64::from(scope));
    fingerprint.optional_string(query.text.as_deref());
    fingerprint.optional_values(query.kinds.as_deref(), |fingerprint, value| {
        fingerprint.byte(match value {
            ItemKind::File => 0,
            ItemKind::Directory => 1,
            ItemKind::ReparsePoint => 2,
        });
    });
    fingerprint.optional_strings(query.extensions.as_deref());
    fingerprint.optional_values(query.policy_tiers.as_deref(), |fingerprint, value| {
        fingerprint.byte(match value {
            PolicyTier::Protected => 0,
            PolicyTier::ReviewRequired => 1,
            PolicyTier::CleanupCandidate => 2,
        });
    });
    fingerprint.optional_strings(query.owner_ids.as_deref());
    fingerprint.optional_string(query.min_bytes.as_deref());
    fingerprint.optional_string(query.modified_before_ms.as_deref());
    fingerprint.byte(match query.sort {
        ItemSort::Name => 0,
        ItemSort::Allocated => 1,
        ItemSort::Logical => 2,
        ItemSort::Modified => 3,
        ItemSort::Type => 4,
        ItemSort::Policy => 5,
        ItemSort::Owner => 6,
    });
    fingerprint.byte(match query.direction {
        SortDirection::Asc => 0,
        SortDirection::Desc => 1,
    });
    fingerprint.0
}

struct Fingerprint(u64);

impl Default for Fingerprint {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Fingerprint {
    fn byte(&mut self, byte: u8) {
        self.0 ^= u64::from(byte);
        self.0 = self.0.wrapping_mul(0x100_0000_01b3);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        for byte in bytes {
            self.byte(*byte);
        }
    }

    fn u64(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    fn optional_string(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.bytes(value.as_bytes());
            }
            None => self.byte(0),
        }
    }

    fn optional_strings(&mut self, values: Option<&[String]>) {
        self.optional_values(values, |fingerprint, value| {
            fingerprint.bytes(value.as_bytes());
        });
    }

    fn optional_values<T>(&mut self, values: Option<&[T]>, mut write: impl FnMut(&mut Self, &T)) {
        match values {
            Some(values) => {
                self.byte(1);
                self.u64(values.len() as u64);
                for value in values {
                    write(self, value);
                }
            }
            None => self.byte(0),
        }
    }
}

fn validate_decimal_filter(value: Option<&str>, field: &str) -> Result<(), ScanFailure> {
    if let Some(value) = value {
        parse_decimal(value, field)?;
    }
    Ok(())
}

fn parse_decimal(value: &str, field: &str) -> Result<u64, ScanFailure> {
    value.parse().map_err(|_| {
        ScanFailure::new(
            "INVALID_QUERY",
            format!("{field} must be an unsigned decimal string"),
            true,
        )
    })
}

fn stale_session() -> ScanFailure {
    ScanFailure::new(
        "STALE_SESSION",
        "The requested item does not belong to the active scan",
        true,
    )
}

fn coverage_warnings(coverage: ScanCoverage) -> Vec<String> {
    match coverage {
        ScanCoverage::Complete => Vec::new(),
        ScanCoverage::Partial => {
            vec!["Partial scan coverage prevents automatic cleanup classification".to_owned()]
        }
        ScanCoverage::PotentiallyStale => {
            vec!["The filesystem changed during scanning; rescan before cleanup".to_owned()]
        }
    }
}

fn recompute_plan_totals(plan: &mut CleanupPlan) -> Result<(), ScanFailure> {
    let mut candidates = 0u64;
    let mut selected_review = 0u64;
    let mut review_potential = 0u64;
    for item in &plan.items {
        let bytes = parse_decimal(&item.reclaimable_bytes, "reclaimable_bytes")?;
        if item.tier == PolicyTier::CleanupCandidate && item.selected {
            candidates = candidates.saturating_add(bytes);
        }
        if item.tier == PolicyTier::ReviewRequired {
            review_potential = review_potential.saturating_add(bytes);
            if item.selected {
                selected_review = selected_review.saturating_add(bytes);
            }
        }
    }
    let target = plan
        .target_bytes
        .as_deref()
        .map(|value| parse_decimal(value, "target_bytes"))
        .transpose()?
        .unwrap_or(0);
    plan.selected_candidate_bytes = candidates.to_string();
    plan.selected_review_bytes = selected_review.to_string();
    plan.review_potential_bytes = review_potential.to_string();
    plan.target_shortfall_bytes = target.saturating_sub(candidates).to_string();
    Ok(())
}

struct WalkFrame {
    next_child: u32,
    restore_len: usize,
    owner: u32,
    rule: Rule,
}

struct SettingsFrame {
    next_child: u32,
    restore_len: usize,
    protected: bool,
}

#[derive(Default)]
struct BucketAccumulator {
    label: String,
    items: u64,
    logical: u64,
    allocated: u64,
}

struct PlanOpportunity {
    index: u32,
    rule: Rule,
    owner: u32,
    bytes: u64,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        arena::{ArenaBuilder, DiscoveredEntry, NO_INDEX},
        scan::{AggregateDimension, ItemSort, SortDirection},
    };
    use clutter_protocol::{
        RAW_NODE_FLAG_DIRECTORY, RAW_NODE_FLAG_ENCRYPTED, RawArenaNode, RawArenaSnapshot,
    };

    use super::*;

    #[test]
    fn query_filters_and_sorts_without_exposing_the_arena() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        let page = analyzer.query(
            &arena,
            &ItemQuery {
                text: Some("cache".to_owned()),
                min_bytes: Some("10".to_owned()),
                sort: ItemSort::Allocated,
                direction: SortDirection::Desc,
                ..ItemQuery::default()
            },
        )?;

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name, "Cache");
        assert_eq!(page.items[0].policy.tier, PolicyTier::CleanupCandidate);
        Ok(())
    }

    #[test]
    fn cursor_is_bound_to_session_scope_filters_and_sorting() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        let mut query = ItemQuery {
            limit: 1,
            ..ItemQuery::default()
        };
        let first = analyzer.query(&arena, &query)?;
        let cursor = first.next_cursor.expect("fixture has a second root child");
        query.cursor = Some(cursor.clone());
        let second = analyzer.query(&arena, &query)?;
        assert_ne!(first.items[0].id, second.items[0].id);

        query.sort = ItemSort::Allocated;
        let error = analyzer
            .query(&arena, &query)
            .expect_err("a cursor cannot be reused after sorting changes");
        assert_eq!(error.code, "INVALID_CURSOR");

        let stale_arena =
            ArenaBuilder::new(PathBuf::from("C:\\"))?.finish("different-session".to_owned());
        let error = analyzer
            .query(
                &stale_arena,
                &ItemQuery {
                    cursor: Some(cursor),
                    ..ItemQuery::default()
                },
            )
            .expect_err("a cursor cannot cross scan sessions");
        assert_eq!(error.code, "STALE_SESSION");
        Ok(())
    }

    #[test]
    fn recursive_queries_observe_cancellation() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        let cancel = AtomicBool::new(true);
        let error = analyzer
            .query_cancellable(
                &arena,
                &ItemQuery {
                    text: Some("cache".to_owned()),
                    query_id: Some("cancel-fixture".to_owned()),
                    ..ItemQuery::default()
                },
                &cancel,
            )
            .expect_err("cancelled queries must not return results");

        assert_eq!(error.code, "QUERY_CANCELLED");
        Ok(())
    }

    #[test]
    fn direct_sort_cache_is_reused_and_invalidated_by_policy_changes() -> Result<(), ScanFailure> {
        let (arena, mut analyzer) = fixture(ScanCoverage::Complete)?;
        let query = ItemQuery {
            sort: ItemSort::Policy,
            ..ItemQuery::default()
        };
        analyzer.query(&arena, &query)?;
        analyzer.query(&arena, &query)?;
        assert_eq!(analyzer.sort_cache.lock().unwrap().entries.len(), 1);

        analyzer.apply_settings(&arena, &AnalyzerSettings::default());
        assert!(analyzer.sort_cache.lock().unwrap().entries.is_empty());
        Ok(())
    }

    #[test]
    fn system_protection_precedes_generated_directory_review() {
        let node = ArenaNode {
            flags: RAW_NODE_FLAG_DIRECTORY,
            ..ArenaNode::default()
        };
        assert_eq!(
            classify(
                r"c:\windows\node_modules",
                "node_modules",
                &node,
                Rule::System,
                NO_OWNER,
                &[],
            ),
            Rule::System
        );
    }

    #[test]
    fn policy_matrix_keeps_unsafe_content_out_of_cleanup_candidates() {
        let plain = ArenaNode::default();
        let encrypted = ArenaNode {
            flags: RAW_NODE_FLAG_ENCRYPTED,
            ..ArenaNode::default()
        };
        let cases = [
            (
                r"c:\users\tester\appdata\local\temp\secret.bin",
                "secret.bin",
                &encrypted,
                Rule::EncryptedData,
            ),
            (
                r"c:\users\tester\backups\disk.vhdx",
                "disk.vhdx",
                &plain,
                Rule::BackupData,
            ),
            (
                r"c:\programdata\microsoft\windows\wer\reportqueue\report.wer",
                "report.wer",
                &plain,
                Rule::WindowsManagedCleanup,
            ),
            (
                r"c:\users\tester\appdata\local\npm-cache\_cacache\content",
                "content",
                &plain,
                Rule::NpmCache,
            ),
            (
                r"c:\users\tester\appdata\local\npm-cache\_logs\debug.log",
                "debug.log",
                &plain,
                Rule::NpmLogs,
            ),
        ];

        for (path, name, node, expected) in cases {
            assert_eq!(
                classify(path, name, node, Rule::Unknown, NO_OWNER, &[]),
                expected,
                "unexpected rule for {path}"
            );
        }
    }

    #[test]
    fn aggregate_and_treemap_are_bounded() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        let aggregate = analyzer.aggregate(
            &arena,
            &StorageAggregateQuery {
                scope_id: None,
                dimension: AggregateDimension::Policy,
                limit: 1,
            },
        )?;
        assert_eq!(aggregate.buckets.len(), 1);

        let treemap = analyzer.treemap(
            &arena,
            &TreemapQuery {
                scope_id: None,
                max_nodes: 1,
            },
        )?;
        assert!(treemap.truncated);
        assert_eq!(treemap.nodes.len(), 2);
        Ok(())
    }

    #[test]
    fn partial_coverage_and_user_protection_block_candidates() -> Result<(), ScanFailure> {
        let (arena, mut analyzer) = fixture(ScanCoverage::Partial)?;
        let cache_id = arena.node_id(2);
        assert_eq!(
            analyzer.item_details(&arena, &cache_id)?.item.policy.tier,
            PolicyTier::ReviewRequired
        );
        analyzer.set_path_protection(
            &arena,
            &PathProtectionRequest {
                node_id: cache_id.clone(),
                protected: true,
            },
        )?;
        assert_eq!(
            analyzer.item_details(&arena, &cache_id)?.item.policy.tier,
            PolicyTier::Protected
        );
        Ok(())
    }

    #[test]
    fn planner_separates_candidate_and_review_totals() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        let plan = analyzer.build_plan(
            &arena,
            &CleanupPlanRequest {
                target_bytes: Some("50".to_owned()),
            },
        )?;

        assert_eq!(plan.selected_candidate_bytes, "100");
        assert_eq!(plan.selected_review_bytes, "0");
        assert_eq!(plan.review_potential_bytes, "200");
        assert_eq!(plan.target_shortfall_bytes, "0");
        Ok(())
    }

    #[test]
    fn protected_child_is_not_hidden_inside_a_candidate_total() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        assert_eq!(
            analyzer
                .item_details(&arena, &arena.node_id(6))?
                .item
                .policy
                .tier,
            PolicyTier::Protected
        );
        assert_eq!(
            analyzer
                .item_details(&arena, &arena.node_id(1))?
                .item
                .policy
                .tier,
            PolicyTier::Protected
        );
        let plan = analyzer.build_plan(&arena, &CleanupPlanRequest { target_bytes: None })?;
        assert_eq!(plan.selected_candidate_bytes, "100");
        assert!(
            plan.items
                .iter()
                .all(|item| !item.node_ids.contains(&arena.node_id(6)))
        );
        Ok(())
    }

    #[test]
    fn persisted_protection_and_dismissal_remove_plan_opportunities() -> Result<(), ScanFailure> {
        let (arena, mut analyzer) = fixture(ScanCoverage::Complete)?;
        let cache_id = arena.node_id(2);
        let mut settings = AnalyzerSettings {
            protected_paths: vec![analyzer.protection_key(&arena, &cache_id)?],
            dismissed_suggestions: Vec::new(),
        };
        analyzer.apply_settings(&arena, &settings);
        assert_eq!(
            analyzer.item_details(&arena, &cache_id)?.item.policy.tier,
            PolicyTier::Protected
        );

        settings.protected_paths.clear();
        analyzer.apply_settings(&arena, &settings);
        let request = DismissSuggestionRequest {
            node_id: cache_id,
            rule_id: "cleanup.user_temp".to_owned(),
            dismissed: true,
        };
        analyzer.dismiss_suggestion(&arena, &request)?;
        let plan = analyzer.build_plan(&arena, &CleanupPlanRequest { target_bytes: None })?;
        assert_eq!(plan.selected_candidate_bytes, "0");
        Ok(())
    }

    #[test]
    fn ntfs_protection_uses_volume_identity_and_relative_path() -> Result<(), ScanFailure> {
        let (arena, mut analyzer) = fixture(ScanCoverage::Complete)?;
        let cache_id = arena.node_id(2);
        let key = analyzer.protection_key(&arena, &cache_id)?;
        assert!(matches!(
            &key,
            ProtectedPath::Identified {
                volume_id,
                relative_path
            } if volume_id == r"\\?\volume{fixture}\" && relative_path.ends_with(r"\temp\cache")
        ));
        analyzer.apply_settings(
            &arena,
            &AnalyzerSettings {
                protected_paths: vec![key.clone()],
                dismissed_suggestions: Vec::new(),
            },
        );
        assert_eq!(analyzer.effective_tier(2), PolicyTier::Protected);

        let mut other_target = fixture_target();
        other_target.volume_id = Some(r"\\?\Volume{other}\".to_owned());
        let mut other_volume = AnalyzerIndex::build(&arena, ScanCoverage::Complete, &other_target);
        other_volume.apply_settings(
            &arena,
            &AnalyzerSettings {
                protected_paths: vec![key],
                dismissed_suggestions: Vec::new(),
            },
        );
        assert_eq!(other_volume.effective_tier(2), PolicyTier::CleanupCandidate);
        Ok(())
    }

    #[test]
    fn plan_edits_recompute_review_totals() -> Result<(), ScanFailure> {
        let (arena, analyzer) = fixture(ScanCoverage::Complete)?;
        let mut plan = analyzer.build_plan(&arena, &CleanupPlanRequest { target_bytes: None })?;
        let review_id = plan
            .items
            .iter()
            .find(|item| item.tier == PolicyTier::ReviewRequired)
            .map(|item| item.id.clone())
            .expect("fixture contains a review item");
        analyzer.edit_plan(
            &arena,
            &mut plan,
            &PlanEdit {
                item_id: review_id,
                selected: true,
            },
        )?;
        assert_eq!(plan.selected_candidate_bytes, "100");
        assert_eq!(plan.selected_review_bytes, "200");
        Ok(())
    }

    #[test]
    fn cleanup_plan_is_bounded_and_reports_omitted_totals() -> Result<(), ScanFailure> {
        let mut builder = ArenaBuilder::new(PathBuf::from(r"C:\Users\tester\source"))?;
        for index in 1..=MAX_PLAN_ITEMS as u32 + 25 {
            builder.push(file(index, 0, &format!("node_modules-{index}"), 1))?;
        }
        let arena = builder.finish("bounded-plan".to_owned());
        let mut analyzer = AnalyzerIndex::build(&arena, ScanCoverage::Complete, &fixture_target());
        for index in 1..arena.node_count() as u32 {
            analyzer.rules[index as usize] = Rule::GeneratedProjectData;
        }

        let plan = analyzer.build_plan(&arena, &CleanupPlanRequest { target_bytes: None })?;

        assert_eq!(plan.items.len(), MAX_PLAN_ITEMS);
        assert!(plan.truncated);
        assert_eq!(plan.omitted_item_count, "25");
        assert_eq!(plan.omitted_review_bytes, "25");
        assert!(plan.items.iter().all(|item| item.node_ids.len() == 1));
        Ok(())
    }

    #[test]
    #[ignore = "allocates and classifies a five-million-entry analyzer session"]
    fn five_million_entry_analyzer_stays_inside_the_rust_budget() -> Result<(), ScanFailure> {
        const ENTRY_COUNT: usize = 5_000_000;
        const NAME_BYTES: usize = 12;
        const RUST_BUDGET: u64 = 512 * 1024 * 1024;

        let mut nodes = Vec::with_capacity(ENTRY_COUNT + 1);
        let mut names = Vec::with_capacity(3 + ENTRY_COUNT * NAME_BYTES);
        names.extend_from_slice(b"C:\\");
        names.resize(3 + ENTRY_COUNT * NAME_BYTES, b'x');
        nodes.push(RawArenaNode {
            name_length: 3,
            parent: NO_INDEX,
            first_child: 1,
            next_sibling: NO_INDEX,
            child_count: ENTRY_COUNT as u32,
            logical_bytes: ENTRY_COUNT as u64,
            allocated_bytes: ENTRY_COUNT as u64,
            flags: RAW_NODE_FLAG_DIRECTORY,
            ..RawArenaNode::default()
        });
        for index in 0..ENTRY_COUNT {
            nodes.push(RawArenaNode {
                name_offset: (3 + index * NAME_BYTES) as u32,
                name_length: NAME_BYTES as u32,
                parent: 0,
                first_child: NO_INDEX,
                next_sibling: if index + 1 == ENTRY_COUNT {
                    NO_INDEX
                } else {
                    (index + 2) as u32
                },
                logical_bytes: 1,
                allocated_bytes: 1,
                ..RawArenaNode::default()
            });
        }

        let arena = ScanArena::from_raw_snapshot(
            PathBuf::from("C:\\"),
            "analyzer-stress".to_owned(),
            RawArenaSnapshot { nodes, names },
        )?;
        let started = std::time::Instant::now();
        let mut analyzer = AnalyzerIndex::build(&arena, ScanCoverage::Complete, &fixture_target());
        let classify_ms = started.elapsed().as_millis();
        let combined = arena
            .estimated_memory_bytes()
            .saturating_add(analyzer.estimated_memory_bytes());
        let query_started = std::time::Instant::now();
        let page = analyzer.query(
            &arena,
            &ItemQuery {
                text: Some("xxxxxxxx".to_owned()),
                sort: ItemSort::Allocated,
                direction: SortDirection::Desc,
                limit: 50,
                ..ItemQuery::default()
            },
        )?;
        let first_search_ms = query_started.elapsed().as_millis();
        let navigation_started = std::time::Instant::now();
        analyzer.query(
            &arena,
            &ItemQuery {
                sort: ItemSort::Name,
                limit: 50,
                ..ItemQuery::default()
            },
        )?;
        let first_navigation_ms = navigation_started.elapsed().as_millis();
        let cached_navigation_started = std::time::Instant::now();
        analyzer.query(
            &arena,
            &ItemQuery {
                sort: ItemSort::Name,
                limit: 50,
                ..ItemQuery::default()
            },
        )?;
        let cached_navigation_ms = cached_navigation_started.elapsed().as_millis();
        let aggregate_started = std::time::Instant::now();
        analyzer.aggregate(
            &arena,
            &StorageAggregateQuery {
                scope_id: None,
                dimension: AggregateDimension::Extension,
                limit: 50,
            },
        )?;
        let aggregate_ms = aggregate_started.elapsed().as_millis();
        let treemap_started = std::time::Instant::now();
        analyzer.treemap(
            &arena,
            &TreemapQuery {
                scope_id: None,
                max_nodes: 5_000,
            },
        )?;
        let treemap_ms = treemap_started.elapsed().as_millis();
        let combined_after_first_view = arena
            .estimated_memory_bytes()
            .saturating_add(analyzer.estimated_memory_bytes());
        analyzer.rules[1..].fill(Rule::GeneratedProjectData);
        let plan_started = std::time::Instant::now();
        let plan = analyzer.build_plan(&arena, &CleanupPlanRequest { target_bytes: None })?;
        let plan_ms = plan_started.elapsed().as_millis();
        println!(
            "entries={} combined_bytes={} first_view_bytes={} classify_ms={} first_search_ms={} first_navigation_ms={} cached_navigation_ms={} aggregate_ms={} treemap_ms={} plan_ms={}",
            arena.entry_count(),
            combined,
            combined_after_first_view,
            classify_ms,
            first_search_ms,
            first_navigation_ms,
            cached_navigation_ms,
            aggregate_ms,
            treemap_ms,
            plan_ms,
        );
        assert!(combined <= RUST_BUDGET);
        assert!(combined_after_first_view <= RUST_BUDGET);
        assert_eq!(page.items.len(), 50);
        assert_eq!(plan.items.len(), MAX_PLAN_ITEMS);
        assert!(plan.truncated);
        assert!(first_search_ms < 300);
        assert!(cached_navigation_ms < 100);
        assert!(treemap_ms < 500);
        Ok(())
    }

    fn fixture(coverage: ScanCoverage) -> Result<(ScanArena, AnalyzerIndex), ScanFailure> {
        let root = PathBuf::from(r"C:\Users\tester\AppData\Local");
        let mut builder = ArenaBuilder::new(root)?;
        builder.push(directory(1, 0, "Temp"))?;
        builder.push(directory(2, 1, "Cache"))?;
        builder.push(file(3, 2, "data.bin", 100))?;
        builder.push(directory(4, 0, "node_modules"))?;
        builder.push(file(5, 4, "package.bin", 200))?;
        builder.push(file(6, 1, "photo.jpg", 50))?;
        let arena = builder.finish("analyzer-fixture".to_owned());
        let analyzer = AnalyzerIndex::build(&arena, coverage, &fixture_target());
        Ok((arena, analyzer))
    }

    fn directory(id: u32, parent: u32, name: &str) -> DiscoveredEntry {
        DiscoveredEntry {
            temporary_id: id,
            parent_temporary_id: Some(parent),
            name: name.to_owned(),
            is_directory: true,
            is_reparse_point: false,
            inaccessible: false,
            is_sparse: false,
            is_compressed: false,
            is_encrypted: false,
            has_named_stream: false,
            logical_bytes: 0,
            allocated_bytes: 0,
            modified_at_ms: None,
            hard_link_count: None,
            hard_link_alias: false,
        }
    }

    fn file(id: u32, parent: u32, name: &str, bytes: u64) -> DiscoveredEntry {
        DiscoveredEntry {
            is_directory: false,
            logical_bytes: bytes,
            allocated_bytes: bytes,
            ..directory(id, parent, name)
        }
    }

    fn fixture_target() -> ScanTarget {
        ScanTarget {
            id: "fixture-volume".to_owned(),
            kind: crate::scan::ScanTargetKind::Volume,
            display_path: "C:\\".to_owned(),
            filesystem: Some("NTFS".to_owned()),
            volume_id: Some(r"\\?\Volume{fixture}\".to_owned()),
            total_bytes: None,
            available_bytes: None,
            fast_scan_available: true,
        }
    }
}
