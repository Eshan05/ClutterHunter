use std::path::PathBuf;

use clutter_protocol::{
    RAW_NODE_FLAG_DIRECTORY, RAW_NODE_FLAG_HARD_LINK_ALIAS, RAW_NODE_FLAG_INACCESSIBLE,
    RAW_NODE_FLAG_REPARSE_POINT, RAW_NODE_NO_INDEX, RawArenaNode, RawArenaSnapshot,
};

use crate::scan::{ItemKind, ItemPage, ItemQuery, ItemRow, ItemSort, ScanFailure, SortDirection};

pub const NO_INDEX: u32 = RAW_NODE_NO_INDEX;
pub type ArenaNode = RawArenaNode;

#[derive(Debug, Clone)]
pub struct DiscoveredEntry {
    pub temporary_id: u32,
    pub parent_temporary_id: Option<u32>,
    pub name: String,
    pub is_directory: bool,
    pub is_reparse_point: bool,
    pub inaccessible: bool,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub modified_at_ms: Option<i64>,
    pub hard_link_count: Option<u32>,
    pub hard_link_alias: bool,
}

#[derive(Debug, Clone, Copy)]
struct NameRef {
    offset: u32,
    length: u32,
}

#[derive(Debug)]
pub struct ArenaBuilder {
    nodes: Vec<ArenaNode>,
    names: Vec<u8>,
    temporary_to_arena: Vec<u32>,
    last_child: Vec<u32>,
    root_path: PathBuf,
}

impl ArenaBuilder {
    pub fn new(root_path: PathBuf) -> Result<Self, ScanFailure> {
        let root_name = root_path.to_string_lossy().into_owned();
        let root_entry = DiscoveredEntry {
            temporary_id: 0,
            parent_temporary_id: None,
            name: root_name,
            is_directory: true,
            is_reparse_point: false,
            inaccessible: false,
            logical_bytes: 0,
            allocated_bytes: 0,
            modified_at_ms: None,
            hard_link_count: None,
            hard_link_alias: false,
        };
        let mut builder = Self {
            nodes: Vec::with_capacity(1024),
            names: Vec::with_capacity(16 * 1024),
            temporary_to_arena: vec![NO_INDEX],
            last_child: Vec::with_capacity(1024),
            root_path,
        };
        builder.push(root_entry)?;
        Ok(builder)
    }

    pub fn push(&mut self, entry: DiscoveredEntry) -> Result<u32, ScanFailure> {
        if self.nodes.len() >= u32::MAX as usize {
            return Err(ScanFailure::new(
                "SCAN_TOO_LARGE",
                "The scan exceeded the 32-bit arena index limit",
                false,
            ));
        }

        let parent = entry
            .parent_temporary_id
            .map(|temporary_id| self.resolve_temporary_id(temporary_id))
            .transpose()?
            .flatten();
        let name = self.push_name(&entry.name)?;
        let arena_id = self.nodes.len() as u32;
        self.nodes.push(new_node(name, parent, &entry));
        self.last_child.push(NO_INDEX);

        let temporary_index = entry.temporary_id as usize;
        if temporary_index >= self.temporary_to_arena.len() {
            self.temporary_to_arena
                .resize(temporary_index.saturating_add(1), NO_INDEX);
        }
        if self.temporary_to_arena[temporary_index] != NO_INDEX {
            return Err(ScanFailure::new(
                "DUPLICATE_SCAN_NODE",
                "The traversal backend emitted a duplicate node identifier",
                false,
            ));
        }
        self.temporary_to_arena[temporary_index] = arena_id;

        if let Some(parent_id) = parent {
            let parent_index = parent_id as usize;
            let previous = self.last_child[parent_index];
            if previous == NO_INDEX {
                self.nodes[parent_index].first_child = arena_id;
            } else {
                self.nodes[previous as usize].next_sibling = arena_id;
            }
            self.last_child[parent_index] = arena_id;
            self.nodes[parent_index].child_count =
                self.nodes[parent_index].child_count.saturating_add(1);
        }

        Ok(arena_id)
    }

    pub fn finish(mut self, session_id: String) -> ScanArena {
        for child_index in (1..self.nodes.len()).rev() {
            let parent = self.nodes[child_index].parent;
            if parent == NO_INDEX {
                continue;
            }
            let logical = self.nodes[child_index].logical_bytes;
            let allocated = self.nodes[child_index].allocated_bytes;
            let parent_node = &mut self.nodes[parent as usize];
            parent_node.logical_bytes = parent_node.logical_bytes.saturating_add(logical);
            parent_node.allocated_bytes = parent_node.allocated_bytes.saturating_add(allocated);
        }

        ScanArena {
            session_id,
            root_path: self.root_path,
            nodes: self.nodes,
            names: self.names,
        }
    }

    pub fn mark_inaccessible(&mut self, temporary_id: u32) -> Result<(), ScanFailure> {
        let arena_id = self
            .resolve_temporary_id(temporary_id)?
            .ok_or_else(|| ScanFailure::new("INVALID_NODE", "Scan node was not found", false))?;
        self.nodes[arena_id as usize].flags |= RAW_NODE_FLAG_INACCESSIBLE;
        Ok(())
    }

    fn resolve_temporary_id(&self, temporary_id: u32) -> Result<Option<u32>, ScanFailure> {
        let resolved = self
            .temporary_to_arena
            .get(temporary_id as usize)
            .copied()
            .filter(|value| *value != NO_INDEX);
        if resolved.is_none() {
            return Err(ScanFailure::new(
                "INVALID_SCAN_PARENT",
                "The traversal backend emitted a child before its parent",
                false,
            ));
        }
        Ok(resolved)
    }

    fn push_name(&mut self, name: &str) -> Result<NameRef, ScanFailure> {
        let offset = u32::try_from(self.names.len()).map_err(|_| {
            ScanFailure::new(
                "NAME_POOL_TOO_LARGE",
                "The scan name pool exceeded its 32-bit offset limit",
                false,
            )
        })?;
        let length = u32::try_from(name.len()).map_err(|_| {
            ScanFailure::new("NAME_TOO_LONG", "A filesystem name was too long", true)
        })?;
        self.names.extend_from_slice(name.as_bytes());
        Ok(NameRef { offset, length })
    }
}

fn new_node(name: NameRef, parent: Option<u32>, entry: &DiscoveredEntry) -> ArenaNode {
    let mut flags = 0;
    if entry.is_directory {
        flags |= RAW_NODE_FLAG_DIRECTORY;
    }
    if entry.is_reparse_point {
        flags |= RAW_NODE_FLAG_REPARSE_POINT;
    }
    if entry.inaccessible {
        flags |= RAW_NODE_FLAG_INACCESSIBLE;
    }
    if entry.hard_link_alias {
        flags |= RAW_NODE_FLAG_HARD_LINK_ALIAS;
    }

    ArenaNode {
        name_offset: name.offset,
        name_length: name.length,
        parent: parent.unwrap_or(NO_INDEX),
        first_child: NO_INDEX,
        next_sibling: NO_INDEX,
        child_count: 0,
        logical_bytes: entry.logical_bytes,
        allocated_bytes: entry.allocated_bytes,
        modified_at_ms: entry.modified_at_ms.unwrap_or(-1),
        hard_link_count: entry.hard_link_count.unwrap_or(0),
        flags,
        reserved: 0,
    }
}

#[derive(Debug)]
pub struct ScanArena {
    session_id: String,
    root_path: PathBuf,
    nodes: Vec<ArenaNode>,
    names: Vec<u8>,
}

impl ScanArena {
    pub fn from_raw_snapshot(
        root_path: PathBuf,
        session_id: String,
        snapshot: RawArenaSnapshot,
    ) -> Result<Self, ScanFailure> {
        snapshot.validate().map_err(invalid_raw_arena)?;
        let RawArenaSnapshot { nodes, names } = snapshot;

        Ok(Self {
            session_id,
            root_path,
            nodes,
            names,
        })
    }

    pub fn entry_count(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    pub fn logical_bytes(&self) -> u64 {
        self.nodes.first().map_or(0, |node| node.logical_bytes)
    }

    pub fn allocated_bytes(&self) -> u64 {
        self.nodes.first().map_or(0, |node| node.allocated_bytes)
    }

    pub fn estimated_memory_bytes(&self) -> u64 {
        let node_bytes = self
            .nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<ArenaNode>());
        u64::try_from(node_bytes.saturating_add(self.names.capacity())).unwrap_or(u64::MAX)
    }

    pub fn query(&self, query: &ItemQuery) -> Result<ItemPage, ScanFailure> {
        let parent = query
            .parent_id
            .as_deref()
            .map(|id| self.parse_node_id(id))
            .transpose()?
            .unwrap_or(0);
        let mut children = self.child_indices(parent)?;
        children.sort_unstable_by(|left, right| {
            let ordering = match query.sort {
                ItemSort::Name => self.name(*left).cmp(self.name(*right)),
                ItemSort::Allocated => self.nodes[*left as usize]
                    .allocated_bytes
                    .cmp(&self.nodes[*right as usize].allocated_bytes),
                ItemSort::Logical => self.nodes[*left as usize]
                    .logical_bytes
                    .cmp(&self.nodes[*right as usize].logical_bytes),
                ItemSort::Modified => self.nodes[*left as usize]
                    .modified_at_ms
                    .cmp(&self.nodes[*right as usize].modified_at_ms),
                ItemSort::Type => item_kind_rank(&self.nodes[*left as usize])
                    .cmp(&item_kind_rank(&self.nodes[*right as usize])),
                ItemSort::Policy | ItemSort::Owner => std::cmp::Ordering::Equal,
            };
            match query.direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        });

        let start = query
            .cursor
            .as_deref()
            .map(|cursor| self.parse_cursor(cursor))
            .transpose()?
            .unwrap_or(0);
        let limit = usize::from(query.limit.clamp(1, 100));
        let end = start.saturating_add(limit).min(children.len());
        let items = children[start..end]
            .iter()
            .map(|index| self.item_row(*index))
            .collect();
        let next_cursor = (end < children.len()).then(|| format!("{}:{end}", self.session_id));

        Ok(ItemPage { items, next_cursor })
    }

    pub(crate) fn child_indices(&self, parent: u32) -> Result<Vec<u32>, ScanFailure> {
        let parent_node = self.nodes.get(parent as usize).ok_or_else(|| {
            ScanFailure::new("INVALID_NODE", "The requested node does not exist", true)
        })?;
        let mut result = Vec::with_capacity(parent_node.child_count as usize);
        let mut current = parent_node.first_child;
        while current != NO_INDEX {
            result.push(current);
            current = self.nodes[current as usize].next_sibling;
        }
        Ok(result)
    }

    pub(crate) fn item_row(&self, index: u32) -> ItemRow {
        let node = &self.nodes[index as usize];
        let name = self.name(index).to_owned();
        let extension = (!node.is_directory() && !node.is_reparse_point())
            .then(|| {
                name.rsplit_once('.')
                    .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
                    .map(|(_, extension)| extension.to_ascii_lowercase())
            })
            .flatten();
        let mut attributes = Vec::with_capacity(3);
        if node.is_reparse_point() {
            attributes.push("reparse_point".to_owned());
        }
        if node.is_inaccessible() {
            attributes.push("inaccessible".to_owned());
        }
        if node.is_hard_link_alias() {
            attributes.push("hard_link_alias".to_owned());
        }

        ItemRow {
            id: self.node_id(index),
            parent_id: (node.parent != NO_INDEX).then(|| self.node_id(node.parent)),
            name,
            display_path: self.path(index).to_string_lossy().into_owned(),
            kind: if node.is_reparse_point() {
                ItemKind::ReparsePoint
            } else if node.is_directory() {
                ItemKind::Directory
            } else {
                ItemKind::File
            },
            logical_bytes: node.logical_bytes.to_string(),
            allocated_bytes: node.allocated_bytes.to_string(),
            modified_at_ms: (node.modified_at_ms >= 0).then(|| node.modified_at_ms.to_string()),
            extension,
            attributes,
            hard_link_count: (node.hard_link_count > 0).then_some(node.hard_link_count),
            child_count: node.is_directory().then_some(node.child_count),
            owner: None,
            policy: Default::default(),
        }
    }

    pub(crate) fn path(&self, index: u32) -> PathBuf {
        if index == 0 {
            return self.root_path.clone();
        }
        let mut parts = Vec::new();
        let mut current = index;
        while current != 0 && current != NO_INDEX {
            parts.push(self.name(current));
            current = self.nodes[current as usize].parent;
        }
        let mut path = self.root_path.clone();
        for part in parts.into_iter().rev() {
            path.push(part);
        }
        path
    }

    pub(crate) fn name(&self, index: u32) -> &str {
        let node = &self.nodes[index as usize];
        let start = node.name_offset as usize;
        let end = start.saturating_add(node.name_length as usize);
        std::str::from_utf8(self.names.get(start..end).unwrap_or_default()).unwrap_or("")
    }

    pub(crate) fn node_id(&self, index: u32) -> String {
        format!("{}:{index}", self.session_id)
    }

    pub(crate) fn parse_node_id(&self, id: &str) -> Result<u32, ScanFailure> {
        let prefix = format!("{}:", self.session_id);
        let index = id
            .strip_prefix(&prefix)
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|index| (*index as usize) < self.nodes.len());
        index.ok_or_else(|| {
            ScanFailure::new(
                "STALE_SESSION",
                "The requested node does not belong to the active scan",
                true,
            )
        })
    }

    fn parse_cursor(&self, cursor: &str) -> Result<usize, ScanFailure> {
        let prefix = format!("{}:", self.session_id);
        cursor
            .strip_prefix(&prefix)
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                ScanFailure::new("STALE_SESSION", "The query cursor is no longer valid", true)
            })
    }

    pub(crate) fn node(&self, index: u32) -> Option<&ArenaNode> {
        self.nodes.get(index as usize)
    }

    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }
}

fn invalid_raw_arena(detail: &str) -> ScanFailure {
    ScanFailure::new("RAW_SNAPSHOT_INVALID", detail, false)
}

fn item_kind_rank(node: &ArenaNode) -> u8 {
    if node.is_reparse_point() {
        2
    } else if node.is_directory() {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u32, parent: u32, name: &str, allocated: u64) -> DiscoveredEntry {
        DiscoveredEntry {
            temporary_id: id,
            parent_temporary_id: Some(parent),
            name: name.to_owned(),
            is_directory: false,
            is_reparse_point: false,
            inaccessible: false,
            logical_bytes: allocated,
            allocated_bytes: allocated,
            modified_at_ms: None,
            hard_link_count: None,
            hard_link_alias: false,
        }
    }

    #[test]
    fn arena_aggregates_and_sorts_root_children() -> Result<(), ScanFailure> {
        let mut builder = ArenaBuilder::new(PathBuf::from("C:\\"))?;
        builder.push(entry(1, 0, "small.txt", 10))?;
        builder.push(entry(2, 0, "large.bin", 30))?;
        let arena = builder.finish("scan-1".to_owned());

        let page = arena.query(&ItemQuery {
            parent_id: None,
            sort: ItemSort::Allocated,
            direction: SortDirection::Desc,
            cursor: None,
            limit: 50,
            ..ItemQuery::default()
        })?;

        assert_eq!(arena.allocated_bytes(), 40);
        assert_eq!(page.items[0].name, "large.bin");
        assert_eq!(page.items[1].display_path, "C:\\small.txt");
        Ok(())
    }

    #[test]
    fn node_layout_stays_compact() {
        assert!(std::mem::size_of::<ArenaNode>() <= 56);
    }

    #[test]
    fn compact_raw_snapshot_is_adopted_without_reassembly() -> Result<(), ScanFailure> {
        let snapshot = RawArenaSnapshot {
            nodes: vec![
                ArenaNode {
                    name_length: 3,
                    parent: NO_INDEX,
                    first_child: 2,
                    next_sibling: NO_INDEX,
                    child_count: 1,
                    logical_bytes: 10,
                    allocated_bytes: 10,
                    flags: RAW_NODE_FLAG_DIRECTORY,
                    ..ArenaNode::default()
                },
                ArenaNode {
                    name_offset: 3,
                    name_length: 4,
                    parent: 2,
                    first_child: NO_INDEX,
                    next_sibling: NO_INDEX,
                    logical_bytes: 10,
                    allocated_bytes: 10,
                    ..ArenaNode::default()
                },
                ArenaNode {
                    name_offset: 7,
                    name_length: 6,
                    parent: 0,
                    first_child: 1,
                    next_sibling: NO_INDEX,
                    child_count: 1,
                    logical_bytes: 10,
                    allocated_bytes: 10,
                    flags: RAW_NODE_FLAG_DIRECTORY,
                    ..ArenaNode::default()
                },
            ],
            names: b"C:\\filefolder".to_vec(),
        };
        let arena =
            ScanArena::from_raw_snapshot(PathBuf::from("C:\\"), "scan-raw".to_owned(), snapshot)?;

        assert_eq!(arena.entry_count(), 2);
        assert_eq!(arena.allocated_bytes(), 10);
        Ok(())
    }

    #[test]
    fn stale_node_ids_are_rejected() -> Result<(), ScanFailure> {
        let arena = ArenaBuilder::new(PathBuf::from("C:\\"))?.finish("scan-2".to_owned());
        let error = arena
            .query(&ItemQuery {
                parent_id: Some("scan-old:0".to_owned()),
                sort: ItemSort::Name,
                direction: SortDirection::Asc,
                cursor: None,
                limit: 50,
                ..ItemQuery::default()
            })
            .expect_err("a stale session must fail");

        assert_eq!(error.code, "STALE_SESSION");
        Ok(())
    }

    #[test]
    #[ignore = "allocates and validates a five-million-entry arena"]
    fn five_million_entry_arena_stays_inside_the_rust_memory_budget() -> Result<(), ScanFailure> {
        const ENTRY_COUNT: usize = 5_000_000;
        const NAME_BYTES: usize = 12;
        const RUST_ARENA_BUDGET: u64 = 512 * 1024 * 1024;

        let mut nodes = Vec::with_capacity(ENTRY_COUNT + 1);
        let mut names = Vec::with_capacity(3 + ENTRY_COUNT * NAME_BYTES);
        names.extend_from_slice(b"C:\\");
        names.resize(3 + ENTRY_COUNT * NAME_BYTES, b'x');
        nodes.push(ArenaNode {
            name_length: 3,
            parent: NO_INDEX,
            first_child: 1,
            next_sibling: NO_INDEX,
            child_count: ENTRY_COUNT as u32,
            logical_bytes: ENTRY_COUNT as u64,
            allocated_bytes: ENTRY_COUNT as u64,
            flags: RAW_NODE_FLAG_DIRECTORY,
            ..ArenaNode::default()
        });
        for index in 0..ENTRY_COUNT {
            nodes.push(ArenaNode {
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
                ..ArenaNode::default()
            });
        }

        let started = std::time::Instant::now();
        let arena = ScanArena::from_raw_snapshot(
            PathBuf::from("C:\\"),
            "stress-five-million".to_owned(),
            RawArenaSnapshot { nodes, names },
        )?;
        println!(
            "entries={} arena_bytes={} adopt_ms={}",
            arena.entry_count(),
            arena.estimated_memory_bytes(),
            started.elapsed().as_millis()
        );
        assert_eq!(arena.entry_count(), ENTRY_COUNT);
        assert!(arena.estimated_memory_bytes() <= RUST_ARENA_BUDGET);
        Ok(())
    }
}
