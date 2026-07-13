use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 6;
pub const RAW_FRAME_LIMIT: usize = 4 * 1024 * 1024;
pub const RAW_NODE_BATCH_SIZE: usize = 32 * 1024;
pub const RAW_NAME_BATCH_SIZE: usize = 2 * 1024 * 1024;
pub const RAW_NODE_NO_INDEX: u32 = u32::MAX;
pub const RAW_NODE_FLAG_DIRECTORY: u16 = 1 << 0;
pub const RAW_NODE_FLAG_REPARSE_POINT: u16 = 1 << 1;
pub const RAW_NODE_FLAG_INACCESSIBLE: u16 = 1 << 2;
pub const RAW_NODE_FLAG_HARD_LINK_ALIAS: u16 = 1 << 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperHello {
    pub protocol_version: u16,
    pub nonce: [u8; 32],
    pub helper_pid: u32,
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawScanStatistics {
    pub mft_record_count: u64,
    pub mft_bytes_read: u64,
    pub mft_data_runs: u64,
    pub ingest_ms: u64,
    pub finalize_ms: u64,
    pub elapsed_ms: u64,
    pub entry_count: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub hard_linked_records: u64,
    pub reparse_points: u64,
    pub named_data_streams: u64,
    pub attribute_list_records: u64,
    pub journal_id_start: Option<u64>,
    pub journal_next_usn_start: Option<i64>,
    pub journal_id_end: Option<u64>,
    pub journal_next_usn_end: Option<i64>,
    pub arena_node_bytes: u64,
    pub arena_name_bytes: u64,
    pub stream_ms: u64,
    pub adopt_ms: u64,
    pub helper_peak_working_set_bytes: u64,
    pub host_peak_working_set_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawScanEntry {
    pub record_id: u64,
    pub link_index: u32,
    pub parent_record_id: u64,
    pub name: String,
    pub is_directory: bool,
    pub is_reparse_point: bool,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub modified_at_ms: Option<i64>,
    pub hard_link_count: u32,
    pub hard_link_alias: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawScanWarning {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawScanPhase {
    Preparing,
    Enumerating,
    Indexing,
    Finalizing,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct RawArenaNode {
    pub name_offset: u32,
    pub name_length: u32,
    pub parent: u32,
    pub first_child: u32,
    pub next_sibling: u32,
    pub child_count: u32,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub modified_at_ms: i64,
    pub hard_link_count: u32,
    pub flags: u16,
    pub reserved: u16,
}

impl RawArenaNode {
    pub fn is_directory(&self) -> bool {
        self.flags & RAW_NODE_FLAG_DIRECTORY != 0
    }

    pub fn is_reparse_point(&self) -> bool {
        self.flags & RAW_NODE_FLAG_REPARSE_POINT != 0
    }

    pub fn is_inaccessible(&self) -> bool {
        self.flags & RAW_NODE_FLAG_INACCESSIBLE != 0
    }

    pub fn is_hard_link_alias(&self) -> bool {
        self.flags & RAW_NODE_FLAG_HARD_LINK_ALIAS != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawArenaSnapshot {
    pub nodes: Vec<RawArenaNode>,
    pub names: Vec<u8>,
}

impl RawArenaSnapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.nodes.is_empty() || self.nodes.len() > u32::MAX as usize {
            return Err("The raw arena node count is invalid");
        }
        let root = &self.nodes[0];
        if root.parent != RAW_NODE_NO_INDEX
            || root.next_sibling != RAW_NODE_NO_INDEX
            || !root.is_directory()
        {
            return Err("The raw arena root is invalid");
        }

        for (index, node) in self.nodes.iter().enumerate() {
            let name_start = node.name_offset as usize;
            let name_end = name_start
                .checked_add(node.name_length as usize)
                .ok_or("A raw arena name range overflowed")?;
            let name = self
                .names
                .get(name_start..name_end)
                .ok_or("A raw arena name was out of bounds")?;
            std::str::from_utf8(name).map_err(|_| "A raw arena name was not valid UTF-8")?;
            if index == 0 {
                continue;
            }
            let parent = node.parent as usize;
            if parent >= self.nodes.len() || parent == index || !self.nodes[parent].is_directory() {
                return Err("A raw arena parent was invalid");
            }
        }

        let mut linked = vec![false; self.nodes.len()];
        linked[0] = true;
        for (parent_index, parent) in self.nodes.iter().enumerate() {
            let mut child = parent.first_child;
            let mut child_count = 0u32;
            while child != RAW_NODE_NO_INDEX {
                let child_index = child as usize;
                let child_node = self
                    .nodes
                    .get(child_index)
                    .ok_or("A raw arena child link was out of bounds")?;
                if linked[child_index] || child_node.parent as usize != parent_index {
                    return Err("The raw arena child links were inconsistent");
                }
                linked[child_index] = true;
                child_count = child_count
                    .checked_add(1)
                    .ok_or("A raw arena child count overflowed")?;
                child = child_node.next_sibling;
            }
            if child_count != parent.child_count {
                return Err("The raw arena child count was inconsistent");
            }
        }
        if linked.iter().any(|linked| !linked) {
            return Err("A raw arena node was not linked from its parent");
        }

        let mut states = vec![0u8; self.nodes.len()];
        states[0] = 2;
        let mut path = Vec::new();
        for start in 1..self.nodes.len() {
            if !self.nodes[start].is_directory() || states[start] != 0 {
                continue;
            }
            path.clear();
            let mut current = start;
            while current != 0 && states[current] == 0 {
                states[current] = 1;
                path.push(current);
                current = self.nodes[current].parent as usize;
            }
            if current != 0 && states[current] == 1 {
                return Err("The raw arena contained a parent cycle");
            }
            for index in path.iter().rev().copied() {
                states[index] = 2;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawScanEnvelope {
    pub protocol_version: u16,
    pub nonce: [u8; 32],
    pub helper_pid: u32,
    pub target: String,
    pub outcome: RawScanOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawScanOutcome {
    Complete {
        arena: RawArenaSnapshot,
        statistics: Box<RawScanStatistics>,
        warnings: Vec<RawScanWarning>,
    },
    Error {
        code: String,
        recoverable: bool,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperMessage {
    Hello(HelperHello),
    Progress {
        phase: RawScanPhase,
        records_seen: u64,
        mft_bytes_read: u64,
        elapsed_ms: u64,
    },
    Warning {
        code: String,
        detail: String,
    },
    ArenaHeader {
        node_count: u32,
        name_bytes: u32,
    },
    NodeBatch {
        sequence: u32,
        nodes: Vec<RawArenaNode>,
    },
    NameBatch {
        sequence: u32,
        bytes: Vec<u8>,
    },
    Complete {
        statistics: RawScanStatistics,
    },
    Error {
        code: String,
        recoverable: bool,
        detail: String,
    },
    Cancel,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_raw_arena() -> RawArenaSnapshot {
        RawArenaSnapshot {
            nodes: vec![
                RawArenaNode {
                    name_length: 3,
                    parent: RAW_NODE_NO_INDEX,
                    first_child: 1,
                    next_sibling: RAW_NODE_NO_INDEX,
                    child_count: 1,
                    flags: RAW_NODE_FLAG_DIRECTORY,
                    ..RawArenaNode::default()
                },
                RawArenaNode {
                    name_offset: 3,
                    name_length: 8,
                    parent: 0,
                    first_child: RAW_NODE_NO_INDEX,
                    next_sibling: RAW_NODE_NO_INDEX,
                    ..RawArenaNode::default()
                },
            ],
            names: b"C:\\file.bin".to_vec(),
        }
    }

    #[test]
    fn protocol_version_tracks_the_binary_wire_format() {
        assert_eq!(PROTOCOL_VERSION, 6);
    }

    #[test]
    fn complete_message_carries_accuracy_counters() {
        let message = HelperMessage::Complete {
            statistics: RawScanStatistics {
                entry_count: 2,
                allocated_bytes: 4096,
                ..RawScanStatistics::default()
            },
        };

        assert!(matches!(message, HelperMessage::Complete { .. }));
    }

    #[test]
    fn raw_entries_keep_physical_alias_accounting_explicit() {
        let entry = RawScanEntry {
            record_id: 42,
            link_index: 1,
            parent_record_id: 5,
            name: "alias.bin".to_owned(),
            is_directory: false,
            is_reparse_point: false,
            logical_bytes: 1024,
            allocated_bytes: 0,
            modified_at_ms: None,
            hard_link_count: 2,
            hard_link_alias: true,
        };

        assert!(entry.hard_link_alias);
        assert_eq!(entry.allocated_bytes, 0);
    }

    #[test]
    fn compact_raw_arena_validates() {
        assert_eq!(valid_raw_arena().validate(), Ok(()));
    }

    #[test]
    fn compact_raw_arena_rejects_inconsistent_links() {
        let mut arena = valid_raw_arena();
        arena.nodes[0].child_count = 2;

        assert_eq!(
            arena.validate(),
            Err("The raw arena child count was inconsistent")
        );
    }

    #[test]
    fn compact_raw_arena_rejects_parent_cycles() {
        let mut arena = valid_raw_arena();
        arena.nodes.push(RawArenaNode {
            name_offset: 3,
            name_length: 8,
            parent: 3,
            first_child: 3,
            next_sibling: RAW_NODE_NO_INDEX,
            child_count: 1,
            flags: RAW_NODE_FLAG_DIRECTORY,
            ..RawArenaNode::default()
        });
        arena.nodes.push(RawArenaNode {
            name_offset: 3,
            name_length: 8,
            parent: 2,
            first_child: 2,
            next_sibling: RAW_NODE_NO_INDEX,
            child_count: 1,
            flags: RAW_NODE_FLAG_DIRECTORY,
            ..RawArenaNode::default()
        });

        assert_eq!(
            arena.validate(),
            Err("The raw arena contained a parent cycle")
        );
    }
}
