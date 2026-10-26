use ble::hci::parameter::*;
use std::collections::BTreeSet;

/// The set of devices that the Link Layer uses for device filtering.
pub struct FilterAcceptList {
    addrs: BTreeSet<FilterAcceptListEntry>,
}

impl FilterAcceptList {
    /// max count of the entries
    pub const MAX_SIZE: u8 = 0xff;

    /// default filter accept list which contains no entry.
    pub fn default() -> Self {
        Self { addrs: BTreeSet::new() }
    }

    /// resets the filter accept list, clears all entries.
    pub fn reset(&mut self) {
        self.addrs.clear();
    }

    /// inserts `entry` to the filter accept list.
    pub fn insert(&mut self, entry: &FilterAcceptListEntry) -> bool {
        if self.addrs.len() == Self::MAX_SIZE as usize {
            return false;
        }
        self.addrs.insert(if entry.0 == AddrKind::AnonymousAdv {
            FilterAcceptListEntry(entry.0.clone(), BdAddr::default())
        } else {
            entry.clone()
        });
        true
    }

    /// removes `entry` from the filter accept list.
    pub fn remove(&mut self, entry: &FilterAcceptListEntry) -> bool {
        self.addrs.remove(entry)
    }

    /// gets the first element in the filter accept list
    pub fn _get_any(&self) -> Option<FilterAcceptListEntry> {
        Some(self.addrs.first()?.clone())
    }
}
