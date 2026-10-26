use std::collections::HashMap;

use ble::hci::parameter::{AddrKind, AdvFilterPolicy, BdAddr};

/// Represents advertising set for LE Extended Advertising.
#[derive(Debug)]
pub struct AdvertisingSet {
    pub advertising_event_properties: u16,
    pub own_addr_kind: AddrKind,
    pub peer_address_type: AddrKind,
    pub peer_address: BdAddr,
    pub advertising_filter_policy: AdvFilterPolicy,
    pub advertising_data: Vec<u8>,
    pub scan_response_data: Vec<u8>,
    pub enabled: bool,
}

impl AdvertisingSet {
    pub fn new(
        advertising_event_properties: u16,
        own_addr_kind: AddrKind,
        peer_address_type: AddrKind,
        peer_address: BdAddr,
        advertising_filter_policy: AdvFilterPolicy,
    ) -> Self {
        Self {
            advertising_event_properties,
            own_addr_kind,
            peer_address_type,
            peer_address,
            advertising_filter_policy,
            advertising_data: Vec::new(),
            scan_response_data: Vec::new(),
            enabled: false,
        }
    }

    pub fn set_param(
        &mut self,
        advertising_event_properties: u16,
        own_addr_kind: AddrKind,
        peer_address_type: AddrKind,
        peer_address: BdAddr,
        advertising_filter_policy: AdvFilterPolicy,
    ) {
        self.advertising_event_properties = advertising_event_properties;
        self.own_addr_kind = own_addr_kind;
        self.peer_address_type = peer_address_type;
        self.peer_address = peer_address;
        self.advertising_filter_policy = advertising_filter_policy;
    }

    pub fn is_connectable(&self) -> bool {
        self.advertising_event_properties & 0b1 != 0
    }

    pub fn is_scannable(&self) -> bool {
        self.advertising_event_properties & 0b10 != 0
    }

    pub fn is_directed(&self) -> bool {
        self.advertising_event_properties & 0b100 != 0
    }

    pub fn is_legacy(&self) -> bool {
        self.advertising_event_properties & 0b10000 != 0
    }
}

pub struct AdvertisingManager {
    pub sets: HashMap<u8, Option<AdvertisingSet>>,
}

impl AdvertisingManager {
    /// max count of the entries
    pub const MAX_SIZE: u8 = 0xf0;

    pub fn new() -> Self {
        Self { sets: HashMap::new() }
    }

    /// Resets inner state.
    pub fn reset(&mut self) {
        self.sets.clear();
    }

    /// Gets the reference of the advertising set with `handle`.
    pub fn get_advertising_set(&self, handle: u8) -> Option<&Option<AdvertisingSet>> {
        if handle >= Self::MAX_SIZE { None } else { self.sets.get(&handle) }
    }

    /// Gets the mutable reference of the advertising set with `handle`.
    pub fn get_advertising_set_mut(&mut self, handle: u8) -> &mut Option<AdvertisingSet> {
        self.sets.entry(handle).or_insert(None)
    }

    /// Removes the advertising set with `handle`.
    pub fn remove_advertising_set(&mut self, handle: u8) {
        self.sets.remove(&handle);
    }

    /// Checks if there's enabled advertising sets.
    pub fn has_enabled(&self) -> bool {
        for (_, adv_set) in &self.sets {
            if let Some(adv_set) = adv_set
                && adv_set.enabled
            {
                return true;
            }
        }
        return false;
    }
}
