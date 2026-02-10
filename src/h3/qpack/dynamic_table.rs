// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! QPACK Dynamic Table implementation per RFC 9204.
//!
//! The dynamic table is a table of header field name-value pairs that is
//! dynamically built up during the processing of header fields. Unlike the
//! static table, entries in the dynamic table are added and removed over time.

use std::collections::VecDeque;

use crate::h3::Http3Error;
use crate::h3::Result;

/// Overhead bytes per entry as defined in RFC 9204 Section 4.1.
/// Each entry in the dynamic table lowers the dynamic table capacity by the
/// sum of the size of its name's value in bytes, the size of its value in bytes,
/// plus 32 bytes.
const ENTRY_OVERHEAD: usize = 32;

/// A single entry in the dynamic table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicTableEntry {
    /// Header field name.
    pub name: Vec<u8>,
    /// Header field value.
    pub value: Vec<u8>,
}

impl DynamicTableEntry {
    /// Create a new dynamic table entry.
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        DynamicTableEntry { name, value }
    }

    /// Calculate the size of this entry as per RFC 9204 Section 4.1.
    /// The size of an entry is the sum of its name's length in bytes,
    /// its value's length in bytes, and 32 bytes.
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// The QPACK dynamic table.
///
/// The dynamic table is indexed in a manner that guarantees indices are unique.
/// The absolute index starts at 0 for the first entry and increases by one
/// for each entry added.
///
/// Entries are stored in a queue, with the oldest entries at the front.
/// When the table capacity is exceeded, oldest entries are evicted.
#[derive(Debug)]
pub struct DynamicTable {
    /// The maximum capacity of the dynamic table in bytes.
    capacity: usize,

    /// Current size of the table in bytes.
    size: usize,

    /// The entries in the table, stored in insertion order.
    /// The front of the queue contains the oldest entries.
    entries: VecDeque<DynamicTableEntry>,

    /// The absolute index of the next entry to be inserted.
    /// This is also the total number of entries ever inserted.
    insert_count: u64,

    /// The number of entries that have been dropped (evicted).
    /// This equals (insert_count - entries.len()) for a non-empty table.
    dropped_count: u64,
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicTable {
    /// Create a new empty dynamic table with zero capacity.
    pub fn new() -> Self {
        DynamicTable {
            capacity: 0,
            size: 0,
            entries: VecDeque::new(),
            insert_count: 0,
            dropped_count: 0,
        }
    }

    /// Create a new dynamic table with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        DynamicTable {
            capacity,
            size: 0,
            entries: VecDeque::new(),
            insert_count: 0,
            dropped_count: 0,
        }
    }

    /// Set the maximum capacity of the dynamic table.
    ///
    /// If the new capacity is less than the current size, entries are evicted
    /// starting from the oldest until the size fits within the new capacity.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        self.evict_to_fit(0);
    }

    /// Get the current capacity of the dynamic table.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current size of the dynamic table in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the number of entries currently in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the insert count (total number of entries ever inserted).
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Insert a new entry into the dynamic table.
    ///
    /// The entry is added to the end of the table (newest entries are at the end).
    /// If inserting the entry would exceed the capacity, oldest entries are
    /// evicted until there is enough space.
    ///
    /// Returns the absolute index of the inserted entry, or an error if the
    /// entry is too large to fit in the table even when empty.
    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) -> Result<u64> {
        let entry = DynamicTableEntry::new(name, value);
        let entry_size = entry.size();

        // If the entry is larger than the capacity, we can't insert it.
        if entry_size > self.capacity {
            return Err(Http3Error::QpackEncoderStreamError);
        }

        // Evict entries until there's enough space.
        self.evict_to_fit(entry_size);

        // Insert the new entry.
        self.entries.push_back(entry);
        self.size += entry_size;

        let absolute_index = self.insert_count;
        self.insert_count += 1;

        Ok(absolute_index)
    }

    /// Insert an entry with a name reference from another table entry.
    ///
    /// This is used when the encoder instruction references a name from
    /// either the static or dynamic table.
    pub fn insert_with_name_ref(
        &mut self,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<u64> {
        self.insert(name, value)
    }

    /// Evict entries from the front of the table until there's enough space
    /// for an entry of the given size.
    fn evict_to_fit(&mut self, needed_size: usize) {
        while self.size + needed_size > self.capacity && !self.entries.is_empty() {
            if let Some(entry) = self.entries.pop_front() {
                self.size -= entry.size();
                self.dropped_count += 1;
            }
        }
    }

    /// Duplicate an existing entry.
    ///
    /// This is used by the "Duplicate" encoder instruction.
    pub fn duplicate(&mut self, absolute_index: u64) -> Result<u64> {
        let entry = self.get(absolute_index)?.clone();
        self.insert(entry.name, entry.value)
    }

    /// Get an entry by its absolute index.
    ///
    /// Returns an error if the index is invalid (either not yet inserted,
    /// or already evicted).
    pub fn get(&self, absolute_index: u64) -> Result<&DynamicTableEntry> {
        // Check if the index has been inserted yet.
        if absolute_index >= self.insert_count {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        // Check if the entry has been evicted.
        if absolute_index < self.dropped_count {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        // Calculate the position in the VecDeque.
        let position = (absolute_index - self.dropped_count) as usize;

        self.entries
            .get(position)
            .ok_or(Http3Error::QpackDecompressionFailed)
    }

    /// Convert a relative index to an absolute index.
    ///
    /// In QPACK, relative indices are used in the encoded field section.
    /// A relative index of 0 refers to the most recently inserted entry,
    /// and the index increases for older entries.
    ///
    /// The `base` is the required insert count at the time of encoding,
    /// which serves as the reference point for relative indexing.
    pub fn relative_to_absolute(&self, relative_index: u64, base: u64) -> Result<u64> {
        if relative_index >= base {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        let absolute_index = base - 1 - relative_index;

        // Validate that the absolute index is within the valid range.
        if absolute_index < self.dropped_count || absolute_index >= self.insert_count {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        Ok(absolute_index)
    }

    /// Convert a post-base index to an absolute index.
    ///
    /// Post-base indices are used to reference entries that were inserted
    /// after the base was established. A post-base index of 0 refers to
    /// the first entry inserted after the base.
    pub fn post_base_to_absolute(&self, post_base_index: u64, base: u64) -> Result<u64> {
        let absolute_index = base + post_base_index;

        // Validate that the absolute index is within the valid range.
        if absolute_index < self.dropped_count || absolute_index >= self.insert_count {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        Ok(absolute_index)
    }

    /// Find an entry by name and value.
    ///
    /// Returns the absolute index of the entry if found.
    /// Searches from newest to oldest entries.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        // Search from newest (back) to oldest (front).
        for (i, entry) in self.entries.iter().enumerate().rev() {
            if entry.name.eq_ignore_ascii_case(name) && entry.value == value {
                return Some(self.dropped_count + i as u64);
            }
        }
        None
    }

    /// Find an entry by name only.
    ///
    /// Returns the absolute index of an entry with a matching name if found.
    /// Searches from newest to oldest entries.
    pub fn find_name(&self, name: &[u8]) -> Option<u64> {
        // Search from newest (back) to oldest (front).
        for (i, entry) in self.entries.iter().enumerate().rev() {
            if entry.name.eq_ignore_ascii_case(name) {
                return Some(self.dropped_count + i as u64);
            }
        }
        None
    }

    /// Clear all entries from the table.
    pub fn clear(&mut self) {
        self.dropped_count += self.entries.len() as u64;
        self.entries.clear();
        self.size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_table_is_empty() {
        let table = DynamicTable::new();
        assert_eq!(table.capacity(), 0);
        assert_eq!(table.size(), 0);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.insert_count(), 0);
    }

    #[test]
    fn set_capacity() {
        let mut table = DynamicTable::new();
        table.set_capacity(1024);
        assert_eq!(table.capacity(), 1024);
    }

    #[test]
    fn insert_single_entry() {
        let mut table = DynamicTable::with_capacity(1024);
        let name = b"content-type".to_vec();
        let value = b"text/html".to_vec();
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;

        let index = table.insert(name.clone(), value.clone()).unwrap();

        assert_eq!(index, 0);
        assert_eq!(table.insert_count(), 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.size(), entry_size);

        let entry = table.get(0).unwrap();
        assert_eq!(entry.name, name);
        assert_eq!(entry.value, value);
    }

    #[test]
    fn insert_multiple_entries() {
        let mut table = DynamicTable::with_capacity(1024);

        let idx0 = table.insert(b"name1".to_vec(), b"value1".to_vec()).unwrap();
        let idx1 = table.insert(b"name2".to_vec(), b"value2".to_vec()).unwrap();
        let idx2 = table.insert(b"name3".to_vec(), b"value3".to_vec()).unwrap();

        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert_eq!(table.len(), 3);
        assert_eq!(table.insert_count(), 3);

        assert_eq!(table.get(0).unwrap().name, b"name1");
        assert_eq!(table.get(1).unwrap().name, b"name2");
        assert_eq!(table.get(2).unwrap().name, b"name3");
    }

    #[test]
    fn eviction_on_capacity() {
        // Entry size = 4 + 4 + 32 = 40 bytes each.
        let mut table = DynamicTable::with_capacity(80); // Room for 2 entries.

        table.insert(b"aaa1".to_vec(), b"bbb1".to_vec()).unwrap();
        table.insert(b"aaa2".to_vec(), b"bbb2".to_vec()).unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.insert_count(), 2);

        // Insert a third entry, which should evict the first.
        table.insert(b"aaa3".to_vec(), b"bbb3".to_vec()).unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.insert_count(), 3);

        // Entry 0 should be evicted.
        assert!(table.get(0).is_err());
        // Entry 1 and 2 should be accessible.
        assert_eq!(table.get(1).unwrap().name, b"aaa2");
        assert_eq!(table.get(2).unwrap().name, b"aaa3");
    }

    #[test]
    fn insert_entry_too_large() {
        let mut table = DynamicTable::with_capacity(40);
        // Entry of size 50 + 32 = 82 bytes, larger than capacity.
        let result = table.insert(b"x".repeat(25).to_vec(), b"y".repeat(25).to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn get_invalid_index() {
        let mut table = DynamicTable::with_capacity(1024);
        table.insert(b"name".to_vec(), b"value".to_vec()).unwrap();

        // Index not yet inserted.
        assert!(table.get(1).is_err());
        // Index never inserted.
        assert!(table.get(100).is_err());
    }

    #[test]
    fn find_entry() {
        let mut table = DynamicTable::with_capacity(1024);
        table.insert(b"name1".to_vec(), b"value1".to_vec()).unwrap();
        table.insert(b"name2".to_vec(), b"value2".to_vec()).unwrap();
        table.insert(b"name1".to_vec(), b"value3".to_vec()).unwrap();

        // Find exact match.
        assert_eq!(table.find(b"name2", b"value2"), Some(1));
        // Find by name (should return newest matching entry).
        assert_eq!(table.find_name(b"name1"), Some(2));
        // Not found.
        assert_eq!(table.find(b"name3", b"value3"), None);
    }

    #[test]
    fn relative_to_absolute_index() {
        let mut table = DynamicTable::with_capacity(1024);
        table.insert(b"name0".to_vec(), b"value0".to_vec()).unwrap();
        table.insert(b"name1".to_vec(), b"value1".to_vec()).unwrap();
        table.insert(b"name2".to_vec(), b"value2".to_vec()).unwrap();

        // With base = 3 (insert_count), relative index 0 = absolute 2.
        assert_eq!(table.relative_to_absolute(0, 3).unwrap(), 2);
        // Relative index 1 = absolute 1.
        assert_eq!(table.relative_to_absolute(1, 3).unwrap(), 1);
        // Relative index 2 = absolute 0.
        assert_eq!(table.relative_to_absolute(2, 3).unwrap(), 0);
        // Relative index >= base is invalid.
        assert!(table.relative_to_absolute(3, 3).is_err());
    }

    #[test]
    fn post_base_to_absolute_index() {
        let mut table = DynamicTable::with_capacity(1024);
        table.insert(b"name0".to_vec(), b"value0".to_vec()).unwrap();
        table.insert(b"name1".to_vec(), b"value1".to_vec()).unwrap();
        table.insert(b"name2".to_vec(), b"value2".to_vec()).unwrap();

        // With base = 1, post-base index 0 = absolute 1.
        assert_eq!(table.post_base_to_absolute(0, 1).unwrap(), 1);
        // Post-base index 1 = absolute 2.
        assert_eq!(table.post_base_to_absolute(1, 1).unwrap(), 2);
        // Post-base index pointing beyond insert_count is invalid.
        assert!(table.post_base_to_absolute(3, 1).is_err());
    }

    #[test]
    fn duplicate_entry() {
        let mut table = DynamicTable::with_capacity(1024);
        table.insert(b"name".to_vec(), b"value".to_vec()).unwrap();

        let dup_idx = table.duplicate(0).unwrap();
        assert_eq!(dup_idx, 1);
        assert_eq!(table.len(), 2);

        let original = table.get(0).unwrap();
        let duplicate = table.get(1).unwrap();
        assert_eq!(original.name, duplicate.name);
        assert_eq!(original.value, duplicate.value);
    }

    #[test]
    fn clear_table() {
        let mut table = DynamicTable::with_capacity(1024);
        table.insert(b"name".to_vec(), b"value".to_vec()).unwrap();
        table.insert(b"name2".to_vec(), b"value2".to_vec()).unwrap();

        table.clear();

        assert_eq!(table.len(), 0);
        assert_eq!(table.size(), 0);
        assert!(table.is_empty());
        // Insert count should remain unchanged.
        assert_eq!(table.insert_count(), 2);
    }

    #[test]
    fn capacity_reduction_evicts() {
        let mut table = DynamicTable::with_capacity(1024);
        // Entry size = 4 + 4 + 32 = 40 bytes each.
        table.insert(b"aaa1".to_vec(), b"bbb1".to_vec()).unwrap();
        table.insert(b"aaa2".to_vec(), b"bbb2".to_vec()).unwrap();
        table.insert(b"aaa3".to_vec(), b"bbb3".to_vec()).unwrap();

        assert_eq!(table.len(), 3);
        assert_eq!(table.size(), 120);

        // Reduce capacity to fit only 2 entries.
        table.set_capacity(80);

        assert_eq!(table.len(), 2);
        assert_eq!(table.size(), 80);
        // First entry should be evicted.
        assert!(table.get(0).is_err());
        assert!(table.get(1).is_ok());
        assert!(table.get(2).is_ok());
    }

    #[test]
    fn case_insensitive_name_matching() {
        let mut table = DynamicTable::with_capacity(1024);
        table
            .insert(b"Content-Type".to_vec(), b"text/html".to_vec())
            .unwrap();

        // Find with different case should work for name.
        assert_eq!(table.find_name(b"content-type"), Some(0));
        assert_eq!(table.find_name(b"CONTENT-TYPE"), Some(0));

        // Find exact should match name case-insensitively but value exactly.
        assert_eq!(table.find(b"content-type", b"text/html"), Some(0));
        // Value must match exactly.
        assert_eq!(table.find(b"content-type", b"TEXT/HTML"), None);
    }
}
