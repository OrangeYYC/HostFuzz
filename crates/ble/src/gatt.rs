use std::{collections::BTreeMap, fmt::Display};

use crate::att::{AttAttributeData, AttAttributeGroupData};

use super::att::AttPacket;
use btuuid::BluetoothUuid;
use tracing::{debug, info};

pub const GATT_PROP_BROADCAST: u8 = 0x01;
pub const GATT_PROP_READ: u8 = 0x02;
pub const GATT_PROP_WRITE_WITHOUT_RESP: u8 = 0x04;
pub const GATT_PROP_WRITE: u8 = 0x08;
pub const GATT_PROP_NOTIFY: u8 = 0x10;
pub const GATT_PROP_INDICATE: u8 = 0x20;
pub const GATT_PROP_AUTH_WRITE: u8 = 0x40;
pub const GATT_PROP_EXTEND: u8 = 0x80;

#[derive(Clone, Debug)]
pub enum GattAction {
    Unknown,
    ExchangeMtu,
    PrimaryServiceDiscovery,
    IncludedServiceDiscovery(u16),
    CharacteristicDiscovery(u16),
}

#[derive(Clone, Debug)]
pub struct GattCharacteristicPresentationFormat {
    pub format: u8,
    pub exponent: u8,
    pub unit: u16,
    pub name_space: u8,
    pub description: u16,
}

/// Includes another service into current.
#[derive(Clone, Debug)]
pub struct GattIncludeDefinition {
    /// included service attribute handle
    pub included_attribute_handle: u16,
    /// end group handle
    pub included_end_group_handle: u16,
    /// service UUID
    pub uuid: BluetoothUuid,
}

impl GattIncludeDefinition {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.included_attribute_handle.to_le_bytes());
        ret.extend_from_slice(&self.included_end_group_handle.to_le_bytes());
        ret.extend_from_slice(&self.uuid.as_le_slice());
        ret
    }
}

/// Defines a GATT service.
#[derive(Clone, Debug)]
pub struct GattServiceDefinition {
    /// uuid of current service
    pub uuid: BluetoothUuid,
    /// represents if the discovery for included service finished
    pub discover_include_finished: bool,
    /// represents if the discovery for characteristic finished
    pub discover_characteristic_finished: bool,
}

impl GattServiceDefinition {
    /// Creates new GATT service.
    pub fn new(uuid: BluetoothUuid, discovered: bool) -> Self {
        Self {
            uuid,
            discover_include_finished: discovered,
            discover_characteristic_finished: discovered,
        }
    }

    /// Creates new primary service entry.
    pub fn new_primary_service_entry(uuid: BluetoothUuid, discovered: bool) -> GattProfileEntry {
        GattProfileEntry::PrimaryService(Self::new(uuid, discovered))
    }

    /// Creates new secondary service entry.
    pub fn new_secondary_service_entry(uuid: BluetoothUuid, discovered: bool) -> GattProfileEntry {
        GattProfileEntry::SecondaryService(Self::new(uuid, discovered))
    }
}

/// Defines a GATT characteristic.
#[derive(Clone, Debug)]
pub struct GattCharacteristicDeclaration {
    /// property of the characteristic
    pub property: u8,
    /// handle for the value
    pub value_handle: u16,
    /// uuid of the characteristic
    pub uuid: BluetoothUuid,
}

impl GattCharacteristicDeclaration {
    /// Creates new GATT characteristic declaration.
    pub fn new(property: u8, value_handle: u16, uuid: BluetoothUuid) -> Self {
        Self { property, value_handle, uuid }
    }

    /// Creates new GATT characteristic declaration profile entry.
    pub fn new_characteristic_declaration_entry(property: u8, value_handle: u16, uuid: BluetoothUuid) -> GattProfileEntry {
        GattProfileEntry::CharacteristicDeclaration(Self::new(property, value_handle, uuid))
    }
}

impl From<GattCharacteristicDeclaration> for Vec<u8> {
    fn from(value: GattCharacteristicDeclaration) -> Self {
        Self::from(&value)
    }
}

impl From<&GattCharacteristicDeclaration> for Vec<u8> {
    fn from(value: &GattCharacteristicDeclaration) -> Self {
        let mut ret = Vec::new();
        ret.push(value.property);
        ret.extend_from_slice(value.value_handle.to_le_bytes().as_slice());
        ret.extend_from_slice(value.uuid.as_le_slice());
        ret
    }
}

impl Display for GattCharacteristicDeclaration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{{property:0x{:02x},value:0x{:04x},uuid:{}}}",
            self.property,
            self.value_handle,
            self.uuid.to_string()
        ))
    }
}

/// Defines the entry of the GATT profile. Every entry has a unique handle.
#[derive(Clone, Debug)]
pub enum GattProfileEntry {
    /// empty or unknown entry
    Unknown,
    /// primary service definition
    PrimaryService(GattServiceDefinition),
    /// secondary service definition
    SecondaryService(GattServiceDefinition),
    /// include definition
    Include(GattIncludeDefinition),
    /// characteristic declaration
    CharacteristicDeclaration(GattCharacteristicDeclaration),
    /// characteristic value
    CharacteristicValue(Vec<u8>),
    /// characteristic extended properties
    CharacteristicExtendedProperties(u8),
    /// characteristic user description
    CharacteristicUserDescription(String),
    /// client characteristic configuration
    ClientCharacteristicConfiguration(u8),
    /// server characteristic configuration
    ServerCharacteristicConfiguration(u8),
    /// characteristic presentation format
    CharacteristicPresentationFormat(GattCharacteristicPresentationFormat),
    /// characteristic aggregate format
    CharacteristicAggregateFormat(Vec<u16>),
}

/// Defines GATT profile.
pub struct GattProfile {
    /// MTU of the ATT/GATT
    pub mtu: Option<u16>,
    /// handle-entry mapping for entire profile
    entries: BTreeMap<u16, GattProfileEntry>,
    /// represents if the discovery finished
    primary_service_discovery_finished: bool,
    /// shortcut for all discovery finished
    all_discovery_finished: bool,
}

impl GattProfile {
    /// Creates profile with no entry.
    pub fn blank() -> Self {
        Self {
            mtu: None,
            entries: BTreeMap::new(),
            primary_service_discovery_finished: false,
            all_discovery_finished: false,
        }
    }

    /// Deletes all entries in the profile.
    pub fn reset(&mut self) {
        self.mtu = None;
        self.entries.clear();
        self.primary_service_discovery_finished = false;
        self.all_discovery_finished = false;
    }

    /// Gets the entry at `handle`.
    pub fn entry(&self, handle: u16) -> &GattProfileEntry {
        match self.entries.get(&handle) {
            Some(v) => v,
            None => &GattProfileEntry::Unknown,
        }
    }

    /// Gets the mutable reference to entry at `handle`. If there's no entry at `handle`, a
    /// [`GattProfileEntry::Unknown`] will be insterted.
    pub fn entry_mut(&mut self, handle: u16) -> &mut GattProfileEntry {
        self.entries.entry(handle).or_insert(GattProfileEntry::Unknown)
    }

    /// Returns all known attribute handles in ascending order.
    pub fn known_handles(&self) -> Vec<u16> {
        self.entries.keys().copied().collect()
    }

    /// Finishes the discovery of all primary service.
    pub fn finish_discover_all_primary_service(&mut self) {
        self.primary_service_discovery_finished = true;
    }

    //==============================================================================================
    // Service management

    /// Adds new primary service to the profile.
    pub fn add_primary_service(&mut self, handle: u16, uuid: BluetoothUuid, discovered: bool) {
        *self.entry_mut(handle) = GattServiceDefinition::new_primary_service_entry(uuid, discovered);
    }

    /// Adds new secondary service to the profile.
    pub fn add_secondary_service(&mut self, uuid: BluetoothUuid, handle: u16, discovered: bool) {
        *self.entry_mut(handle) = GattServiceDefinition::new_secondary_service_entry(uuid, discovered);
    }

    /// Gets list of all primary service between `start` and `end`.
    pub fn get_primary_service_range(&mut self, start: u16, end: u16) -> Option<(u8, AttAttributeGroupData)> {
        if start > end {
            return None;
        }
        for (handle, entry) in self.entries.range(start..=end) {
            if let GattProfileEntry::PrimaryService(service) = entry {
                let attribute_value = service.uuid.as_le_slice().to_vec();
                return Some((
                    0x2 + 0x2 + attribute_value.len() as u8,
                    AttAttributeGroupData {
                        attribute_handle: *handle,
                        end_group_handle: self.service_group_end(*handle),
                        attribute_value,
                    },
                ));
            }
        }
        None
    }

    /// Gets the group end of the service at `handle`.
    pub fn service_group_end(&self, handle: u16) -> u16 {
        if handle < 0xffff {
            // check entries from group start until we find blank entry or other service
            for (h, entry) in self.entries.range((handle + 1)..=0xffff) {
                match entry {
                    GattProfileEntry::Unknown | GattProfileEntry::PrimaryService(_) | GattProfileEntry::SecondaryService(_) => return *h - 1,
                    _ => continue,
                }
            }
        }
        0xffff
    }

    /// Finishes the discovery of all includes of service at `handle`.
    pub fn finish_find_included_service(&mut self, handle: u16) {
        if let GattProfileEntry::PrimaryService(s) = self.entry_mut(handle) {
            s.discover_include_finished = true;
        }
    }

    /// Finishes the discovery of all characteristic of service at `handle`.
    pub fn finish_discover_all_characteristic_of_service(&mut self, handle: u16) {
        if let GattProfileEntry::PrimaryService(s) = self.entry_mut(handle) {
            s.discover_characteristic_finished = true;
        }
    }

    /// Gets next start handle for primary service discovery.
    pub fn next_primary_service_discovery_start(&self) -> u16 {
        let mut handle = 0x0001;
        while let GattProfileEntry::PrimaryService(_) = self.entry(handle) {
            handle = self.service_group_end(handle);
            if handle == 0xffff {
                return handle;
            }
            handle = handle + 1;
        }
        return handle;
    }

    /// Gets next start handle for include or characteristic.
    pub fn next_discovery_start(&self, group_start: u16, group_end: u16) -> u16 {
        if group_end <= group_start {
            return group_start.saturating_add(1);
        }
        if group_start + 1 < group_end {
            if let Some((h, _)) = self.entries.range((group_start + 1)..=group_end).last() {
                if *h != group_end {
                    return h + 1;
                }
            } else {
                return group_start + 1;
            }
        }
        return group_end;
    }

    //==============================================================================================
    // Included service management

    /// Gets first included service declation entry between `start` and `end`.
    pub fn get_included_service_range(&mut self, start: u16, end: u16) -> Option<(u8, AttAttributeData)> {
        if start > end {
            return None;
        }
        for (handle, entry) in self.entries.range(start..=end) {
            if let GattProfileEntry::Include(include) = entry {
                let attribute_value = include.to_vec();
                return Some((
                    0x2 + attribute_value.len() as u8,
                    AttAttributeData {
                        attribute_handle: *handle,
                        attribute_value,
                    },
                ));
            }
        }
        None
    }

    //==============================================================================================
    // Characteristic management

    /// Adds new characteristic to the profile.
    pub fn add_characteristic(&mut self, handle: u16, property: u8, value_handle: u16, uuid: BluetoothUuid) {
        *self.entry_mut(handle) = GattCharacteristicDeclaration::new_characteristic_declaration_entry(property, value_handle, uuid);
        *self.entry_mut(value_handle) = GattProfileEntry::CharacteristicValue(Vec::new());
    }

    /// Gets the group end of the characteristic at `handle`.
    pub fn characteristic_group_end(&self, handle: u16) -> u16 {
        if handle < 0xffff {
            // check entries from group start until we find blank entry or other service / characteristic
            for (h, entry) in self.entries.range((handle + 1)..=0xffff) {
                match entry {
                    GattProfileEntry::Unknown
                    | GattProfileEntry::PrimaryService(_)
                    | GattProfileEntry::SecondaryService(_)
                    | GattProfileEntry::Include(_)
                    | GattProfileEntry::CharacteristicDeclaration(_) => return *h - 1,
                    _ => continue,
                }
            }
        }
        0xffff
    }

    /// Gets first characteristic declation entry between `start` and `end`.
    pub fn get_characteristic_range(&mut self, start: u16, end: u16) -> Option<(&u16, &GattCharacteristicDeclaration)> {
        if start > end {
            return None;
        }
        for (handle, entry) in self.entries.range(start..=end) {
            if let GattProfileEntry::CharacteristicDeclaration(declaration) = entry {
                return Some((handle, declaration));
            }
        }
        None
    }

    /// Gets first characteristic descriptor entry between `start` and `end`.
    pub fn get_characteristic_descriptor_range(&mut self, start: u16, end: u16) -> Option<(&u16, BluetoothUuid)> {
        if start > end {
            return None;
        }
        for (handle, entry) in self.entries.range(start..=end) {
            match entry {
                GattProfileEntry::CharacteristicExtendedProperties(_) => {
                    return Some((handle, btuuid::descriptors::CHARACTERISTIC_EXTENDED_PROPERTIES.into()));
                }
                GattProfileEntry::CharacteristicUserDescription(_) => {
                    return Some((handle, btuuid::descriptors::CHARACTERISTIC_USER_DESCRIPTION.into()));
                }
                GattProfileEntry::ClientCharacteristicConfiguration(_) => {
                    return Some((handle, btuuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION.into()));
                }
                GattProfileEntry::ServerCharacteristicConfiguration(_) => {
                    return Some((handle, btuuid::descriptors::SERVER_CHARACTERISTIC_CONFIGURATION.into()));
                }
                GattProfileEntry::CharacteristicPresentationFormat(_) => {
                    return Some((handle, btuuid::descriptors::CHARACTERISTIC_PRESENTATION_FORMAT.into()));
                }
                GattProfileEntry::CharacteristicAggregateFormat(_) => {
                    return Some((handle, btuuid::descriptors::CHARACTERISTIC_AGGREGATE_FORMAT.into()));
                }
                _ => continue,
            }
        }
        None
    }

    //==============================================================================================
    // Discovery management

    /// Gets next discovery action. If all discovery is finished, `None` is returned.
    pub fn next_discovery_action(&mut self) -> Option<(GattAction, AttPacket)> {
        if self.all_discovery_finished {
            return None;
        }

        if self.mtu.is_none() {
            debug!("GATT exchange MTU");
            return Some((GattAction::ExchangeMtu, AttPacket::ExchangeMtuReq { client_rx_mtu: 0x00FB }));
        }

        if !self.primary_service_discovery_finished {
            let starting_handle = self.next_primary_service_discovery_start();
            debug!("GATT primary service discovery: 0x{:04x}-0xffff", starting_handle);
            return Some((
                GattAction::PrimaryServiceDiscovery,
                AttPacket::ReadByGroupTypeReq {
                    starting_handle,
                    ending_handle: 0xffff,
                    attribute_group_type: btuuid::declarations::PRIMARY_SERVICE.as_le_bytes().into(),
                },
            ));
        }

        let mut handle = 0x0001;
        while let GattProfileEntry::PrimaryService(service) = self.entry(handle).clone() {
            let group_end_handle = self.service_group_end(handle);
            let starting_handle = self.next_discovery_start(handle, group_end_handle);

            if !service.discover_include_finished {
                if starting_handle > group_end_handle {
                    self.finish_find_included_service(handle);
                    continue;
                }
                debug!("GATT included service discovery: 0x{:04x}-0x{:04x}", starting_handle, group_end_handle);
                return Some((
                    GattAction::IncludedServiceDiscovery(handle),
                    AttPacket::ReadByTypeReq {
                        starting_handle,
                        ending_handle: group_end_handle,
                        attribute_type: btuuid::declarations::INCLUDE.as_le_bytes().into(),
                    },
                ));
            }

            if !service.discover_characteristic_finished {
                if starting_handle > group_end_handle {
                    self.finish_discover_all_characteristic_of_service(handle);
                    continue;
                }
                debug!("GATT characteristic discovery: 0x{:04x}-0x{:04x}", starting_handle, group_end_handle);
                return Some((
                    GattAction::CharacteristicDiscovery(handle),
                    AttPacket::ReadByTypeReq {
                        starting_handle,
                        ending_handle: group_end_handle,
                        attribute_type: btuuid::declarations::CHARACTERISTIC.as_le_bytes().into(),
                    },
                ));
            }

            if group_end_handle == 0xffff {
                break;
            } else {
                handle = group_end_handle + 1;
            }
        }

        self.all_discovery_finished = true;
        self.print_discovery_result();
        None
    }

    /// Prints discovery result to console.
    pub fn print_discovery_result(&self) {
        let mut handle = 0x0001;
        while let GattProfileEntry::PrimaryService(service) = self.entry(handle) {
            let group_end_handle = self.service_group_end(handle);
            info!(
                "  [0x{:04x}] Primary Service {} (0x{:04x}-0x{:04x})",
                handle,
                service.uuid.to_string(),
                handle,
                group_end_handle
            );

            if handle < group_end_handle {
                for (h, entry) in self.entries.range((handle + 1)..=group_end_handle) {
                    if let GattProfileEntry::CharacteristicDeclaration(c) = entry {
                        info!("    [0x{:04x}] Characteristic {}", h, c.uuid.to_string());
                        info!("      [0x{:04x}] Vaule", c.value_handle);
                    }
                }
            }

            if group_end_handle == 0xffff {
                break;
            } else {
                handle = group_end_handle + 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GattProfile;
    use btuuid::BluetoothUuid;

    #[test]
    fn empty_service_ranges_do_not_panic() {
        let mut profile = GattProfile::blank();
        profile.add_primary_service(0x0001, BluetoothUuid::Uuid16(0x180D.into()), false);
        profile.add_primary_service(0x0002, BluetoothUuid::Uuid16(0x180F.into()), false);
        profile.mtu = Some(23);
        profile.finish_discover_all_primary_service();

        assert!(profile.get_included_service_range(0x0002, 0x0001).is_none());
        assert!(profile.get_characteristic_range(0x0002, 0x0001).is_none());
        assert!(profile.get_characteristic_descriptor_range(0x0002, 0x0001).is_none());

        let _ = profile.next_discovery_action();

        profile.print_discovery_result();
    }
}
