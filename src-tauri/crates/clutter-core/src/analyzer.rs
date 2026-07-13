use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
};

use serde::{Deserialize, Serialize};

use crate::{
    arena::{ArenaNode, NO_INDEX, ScanArena},
    ownership::{OwnerRecord, canonical_path, discover_owners},
    scan::{
        AggregateDimension, CleanupPlan, CleanupPlanRequest, DismissSuggestionRequest, ItemDetails,
        ItemKind, ItemPage, ItemQuery, ItemRow, ItemSort, OwnerMatchKind, OwnerSummary,
        PathProtectionRequest, PlanActionKind, PlanEdit, PlanItem, PolicyEvidence, PolicyTier,
        ScanCoverage, ScanFailure, SortDirection, StorageAggregate, StorageAggregateQuery,
        StorageBucket, TreemapNode, TreemapQuery, TreemapSlice,
    },
};

const RULE_VERSION: &str = "1";
const NO_OWNER: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
enum Rule {
    Unknown,
    ScanRoot,
    System,
    InstalledApplication,
    PersonalData,
    SourceData,
    UserProtected,
    MixedContent,
    GeneratedProjectData,
    RecycleBin,
    UserTemp,
    BrowserCache,
    CrashReports,
    ScoopCache,
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
            Self::UserProtected => "protected.user_path",
            Self::MixedContent => "protected.mixed_cleanup_content",
            Self::GeneratedProjectData => "review.generated_project_data",
            Self::RecycleBin => "review.recycle_bin",
            Self::UserTemp => "cleanup.user_temp",
            Self::BrowserCache => "cleanup.browser_cache",
            Self::CrashReports => "cleanup.crash_reports",
            Self::ScoopCache => "cleanup.scoop_cache",
            Self::OllamaModels => "review.ollama_models",
            Self::OllamaBlobs => "protected.ollama_shared_blobs",
        }
    }

    fn tier(self) -> PolicyTier {
        match self {
            Self::GeneratedProjectData | Self::RecycleBin | Self::OllamaModels => {
                PolicyTier::ReviewRequired
            }
            Self::UserTemp | Self::BrowserCache | Self::CrashReports | Self::ScoopCache => {
                PolicyTier::CleanupCandidate
            }
            _ => PolicyTier::Protected,
        }
    }

    fn action(self) -> PlanActionKind {
        match self {
            Self::ScoopCache => PlanActionKind::RunScoopCache,
            Self::OllamaModels => PlanActionKind::RunOllamaRm,
            Self::InstalledApplication => PlanActionKind::OpenWindowsAppsSettings,
            Self::System | Self::RecycleBin => PlanActionKind::OpenWindowsStorageSettings,
            Self::Unknown
            | Self::ScanRoot
            | Self::PersonalData
            | Self::SourceData
            | Self::UserProtected
            | Self::MixedContent
            | Self::GeneratedProjectData
            | Self::OllamaBlobs => PlanActionKind::OpenLocation,
            Self::UserTemp | Self::BrowserCache | Self::CrashReports => PlanActionKind::Inspect,
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::UserTemp => 0,
            Self::BrowserCache => 1,
            Self::CrashReports => 2,
            Self::ScoopCache => 3,
            _ => u8::MAX,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::GeneratedProjectData => "Generated project data",
            Self::RecycleBin => "Recycle Bin contents",
            Self::UserTemp => "User temporary files",
            Self::BrowserCache => "Browser caches",
            Self::CrashReports => "Crash reports",
            Self::ScoopCache => "Scoop download cache",
            Self::OllamaModels => "Ollama models",
            _ => "Storage item",
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalyzerSettings {
    pub protected_paths: Vec<String>,
    pub dismissed_suggestions: Vec<DismissedSuggestion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DismissedSuggestion {
    pub canonical_path: String,
    pub rule_id: String,
}

impl AnalyzerIndex {
    pub fn build(arena: &ScanArena, coverage: ScanCoverage) -> Self {
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
        self.user_protected.fill(false);
        if !settings.protected_paths.is_empty() && arena.node_count() > 0 {
            let mut path = canonical_path(arena.path(0));
            let root_protected = settings
                .protected_paths
                .iter()
                .any(|protected| is_same_or_descendant(&path, protected));
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
                        .any(|root| is_same_or_descendant(&path, root));
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
        u64::try_from(fixed).unwrap_or(u64::MAX)
    }

    pub fn protection_key(&self, arena: &ScanArena, node_id: &str) -> Result<String, ScanFailure> {
        arena
            .parse_node_id(node_id)
            .map(|index| canonical_path(arena.path(index)))
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
        let scope = query
            .scope_id
            .as_deref()
            .or(query.parent_id.as_deref())
            .map(|id| arena.parse_node_id(id))
            .transpose()?
            .unwrap_or(0);
        validate_decimal_filter(query.min_bytes.as_deref(), "min_bytes")?;
        validate_decimal_filter(query.modified_before_ms.as_deref(), "modified_before_ms")?;
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
        let mut candidates = if recursive {
            descendants(arena, scope)
        } else {
            arena.child_indices(scope)?
        };
        candidates.retain(|index| self.matches(arena, *index, query));
        candidates.sort_unstable_by(|left, right| {
            let ordering = self.compare(arena, *left, *right, query.sort);
            let ordering = match query.direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            };
            ordering.then_with(|| left.cmp(right))
        });

        let start = query
            .cursor
            .as_deref()
            .map(|cursor| parse_query_cursor(arena, cursor))
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
        let next_cursor =
            (end < candidates.len()).then(|| format!("{}:query:{end}", arena.session_id()));
        Ok(ItemPage { items, next_cursor })
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
        let indices = if query.dimension == AggregateDimension::Kind {
            arena.child_indices(scope)?
        } else {
            descendants(arena, scope)
                .into_iter()
                .filter(|index| arena.node(*index).is_some_and(|node| !node.is_directory()))
                .collect()
        };
        let mut buckets = BTreeMap::<String, BucketAccumulator>::new();
        for index in indices {
            let Some(node) = arena.node(index) else {
                continue;
            };
            let (key, label) = self.aggregate_key(arena, index, query.dimension);
            let bucket = buckets.entry(key).or_insert_with(|| BucketAccumulator {
                label,
                ..BucketAccumulator::default()
            });
            bucket.items = bucket.items.saturating_add(1);
            bucket.logical = bucket.logical.saturating_add(node.logical_bytes);
            bucket.allocated = bucket.allocated.saturating_add(node.allocated_bytes);
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
                    key,
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
        let mut children = arena.child_indices(scope)?;
        children.sort_unstable_by(|left, right| {
            arena
                .node(*right)
                .map_or(0, |node| node.allocated_bytes)
                .cmp(&arena.node(*left).map_or(0, |node| node.allocated_bytes))
                .then_with(|| arena.name(*left).cmp(arena.name(*right)))
        });
        let limit = usize::from(query.max_nodes.clamp(1, 5_000));
        let hidden = children.split_off(limit.min(children.len()));
        let other_allocated = hidden.iter().fold(0u64, |total, index| {
            total.saturating_add(arena.node(*index).map_or(0, |node| node.allocated_bytes))
        });
        let mut nodes: Vec<_> = children
            .into_iter()
            .map(|index| self.treemap_node(arena, index, Some(scope)))
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
            truncated: !hidden.is_empty(),
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
        let mut groups = BTreeMap::<(Rule, u32), Opportunity>::new();
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
            let group = groups.entry((rule, owner)).or_default();
            group.nodes.push(index);
            group.bytes = group.bytes.saturating_add(node.allocated_bytes);
        }
        let mut opportunities: Vec<_> = groups.into_iter().collect();
        opportunities.sort_unstable_by(|left, right| {
            plan_tier_rank(left.0.0.tier())
                .cmp(&plan_tier_rank(right.0.0.tier()))
                .then_with(|| left.0.0.priority().cmp(&right.0.0.priority()))
                .then_with(|| right.1.bytes.cmp(&left.1.bytes))
                .then_with(|| left.0.cmp(&right.0))
        });

        let mut selected_candidate = 0u64;
        let mut review_potential = 0u64;
        let mut items = Vec::with_capacity(opportunities.len());
        for ((rule, _owner), opportunity) in opportunities {
            let tier = rule.tier();
            let selected = tier == PolicyTier::CleanupCandidate
                && target.is_none_or(|target| selected_candidate < target);
            if selected {
                selected_candidate = selected_candidate.saturating_add(opportunity.bytes);
            }
            if tier == PolicyTier::ReviewRequired {
                review_potential = review_potential.saturating_add(opportunity.bytes);
            }
            let evidence = opportunity
                .nodes
                .iter()
                .take(3)
                .map(|index| self.policy_evidence(arena, *index))
                .collect();
            items.push(PlanItem {
                id: format!("{}:plan:{}", arena.session_id(), items.len()),
                node_ids: opportunity
                    .nodes
                    .iter()
                    .map(|index| arena.node_id(*index))
                    .collect(),
                title: rule.title().to_owned(),
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
        let mut facts = vec![format!("Matched bundled policy rule {}", rule.id())];
        if let Some(node) = arena.node(index) {
            facts.push(format!("Allocated bytes: {}", node.allocated_bytes));
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
            let extension = extension(arena.name(index));
            if !extensions.iter().any(|candidate| {
                extension
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case(candidate))
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

    fn aggregate_key(
        &self,
        arena: &ScanArena,
        index: u32,
        dimension: AggregateDimension,
    ) -> (String, String) {
        match dimension {
            AggregateDimension::Extension => extension(arena.name(index))
                .map(|extension| (extension.clone(), extension))
                .unwrap_or_else(|| ("(none)".to_owned(), "No extension".to_owned())),
            AggregateDimension::Owner => self
                .owners
                .get(self.node_owners[index as usize] as usize)
                .map(|owner| (owner.summary.id.clone(), owner.summary.name.clone()))
                .unwrap_or_else(|| ("unknown".to_owned(), "Unknown owner".to_owned())),
            AggregateDimension::Policy => {
                let tier = self.effective_tier(index);
                (format!("{tier:?}").to_lowercase(), format!("{tier:?}"))
            }
            AggregateDimension::Kind => {
                let kind = arena.node(index).map_or(ItemKind::File, item_kind);
                (format!("{kind:?}").to_lowercase(), format!("{kind:?}"))
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
    let extension = extension(&name);
    if is_personal_extension(extension.as_deref()) {
        return Rule::PersonalData;
    }
    if is_source_name(&name) || is_source_extension(extension.as_deref()) {
        return Rule::SourceData;
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
    if contains_subtree(path, "\\appdata\\local\\crashdumps") {
        return Rule::CrashReports;
    }
    if contains_subtree(path, "\\appdata\\local\\temp") {
        return Rule::UserTemp;
    }
    if is_browser_cache(path) {
        return Rule::BrowserCache;
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
    if parent_rule == Rule::System || is_system_path(path) {
        return Rule::System;
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

fn is_browser_cache(path: &str) -> bool {
    (contains_subtree(path, "\\google\\chrome\\user data")
        || contains_subtree(path, "\\microsoft\\edge\\user data")
        || contains_subtree(path, "\\mozilla\\firefox\\profiles"))
        && ["cache", "cache_data", "code cache", "gpucache"]
            .iter()
            .any(|component| has_component(path, component))
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

fn extension(name: &str) -> Option<String> {
    name.rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(_, extension)| extension.to_lowercase())
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

fn parse_query_cursor(arena: &ScanArena, cursor: &str) -> Result<usize, ScanFailure> {
    let prefix = format!("{}:query:", arena.session_id());
    cursor
        .strip_prefix(&prefix)
        .and_then(|value| value.parse().ok())
        .ok_or_else(stale_session)
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

#[derive(Default)]
struct Opportunity {
    nodes: Vec<u32>,
    bytes: u64,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        arena::{ArenaBuilder, DiscoveredEntry, NO_INDEX},
        scan::{AggregateDimension, ItemSort, SortDirection},
    };
    use clutter_protocol::{RAW_NODE_FLAG_DIRECTORY, RawArenaNode, RawArenaSnapshot};

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
        let analyzer = AnalyzerIndex::build(&arena, ScanCoverage::Complete);
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
        println!(
            "entries={} combined_bytes={} classify_ms={} first_search_ms={}",
            arena.entry_count(),
            combined,
            classify_ms,
            query_started.elapsed().as_millis()
        );
        assert!(combined <= RUST_BUDGET);
        assert_eq!(page.items.len(), 50);
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
        let analyzer = AnalyzerIndex::build(&arena, coverage);
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
}
