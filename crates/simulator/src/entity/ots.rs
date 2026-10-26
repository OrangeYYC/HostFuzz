use ble::gatt::{self, GattProfile, GattProfileEntry};
use btuuid::BluetoothUuid;

pub const OTS_FEATURE_HANDLE: u16 = 0x0003;
pub const OTS_NAME_HANDLE: u16 = 0x0005;
pub const OTS_TYPE_HANDLE: u16 = 0x0007;
pub const OTS_SIZE_HANDLE: u16 = 0x0009;
pub const OTS_ID_HANDLE: u16 = 0x000B;
pub const OTS_PROPERTIES_HANDLE: u16 = 0x000D;
pub const OTS_OACP_HANDLE: u16 = 0x000F;
pub const OTS_OACP_CCCD_HANDLE: u16 = 0x0010;
pub const OTS_OLCP_HANDLE: u16 = 0x0012;
pub const OTS_OLCP_CCCD_HANDLE: u16 = 0x0013;

pub const OTS_PSM: u16 = 0x0025;
pub const LE_COC_INITIAL_CREDITS: u16 = 0x0020;
pub const LE_COC_REFILL_CREDITS: u16 = 0x0008;

pub const GATT_CCCD_NOTIFY: u16 = 0x0001;
pub const GATT_CCCD_INDICATE: u16 = 0x0002;

const OTS_DEFAULT_CURRENT_SIZE: u32 = 0x20;
const OTS_DEFAULT_ALLOC_SIZE: u32 = 0x20;
const OACP_RES_SUCCESS: u8 = 0x01;
const OACP_RES_OPCODE_NOT_SUPPORTED: u8 = 0x02;
const OACP_RES_INVALID_PARAMETER: u8 = 0x03;

#[derive(Debug, Clone, Copy)]
struct PendingOacpWrite {
    offset: u32,
    len: u32,
    received: u32,
}

#[derive(Debug, Clone)]
pub struct OtsEntity {
    pending_oacp_read: Option<(u32, u32)>,
    pending_oacp_read_ready: bool,
    pending_oacp_write: Option<PendingOacpWrite>,
    object_data: Vec<u8>,
    object_current_size: u32,
    object_alloc_size: u32,
}

pub fn install_ots_service(gatt_profile: &mut GattProfile) {
    // OTS service (0x1825)
    gatt_profile.add_primary_service(0x0001, BluetoothUuid::Uuid16(0x1825.into()), true);
    gatt_profile.add_characteristic(0x0002, gatt::GATT_PROP_READ, OTS_FEATURE_HANDLE, BluetoothUuid::Uuid16(0x2ABD.into()));
    gatt_profile.add_characteristic(
        0x0004,
        gatt::GATT_PROP_READ | gatt::GATT_PROP_WRITE,
        OTS_NAME_HANDLE,
        BluetoothUuid::Uuid16(0x2ABE.into()),
    );
    gatt_profile.add_characteristic(0x0006, gatt::GATT_PROP_READ, OTS_TYPE_HANDLE, BluetoothUuid::Uuid16(0x2ABF.into()));
    gatt_profile.add_characteristic(0x0008, gatt::GATT_PROP_READ, OTS_SIZE_HANDLE, BluetoothUuid::Uuid16(0x2AC0.into()));
    gatt_profile.add_characteristic(0x000A, gatt::GATT_PROP_READ, OTS_ID_HANDLE, BluetoothUuid::Uuid16(0x2AC3.into()));
    gatt_profile.add_characteristic(0x000C, gatt::GATT_PROP_READ, OTS_PROPERTIES_HANDLE, BluetoothUuid::Uuid16(0x2AC4.into()));
    gatt_profile.add_characteristic(
        0x000E,
        gatt::GATT_PROP_WRITE | gatt::GATT_PROP_INDICATE,
        OTS_OACP_HANDLE,
        BluetoothUuid::Uuid16(0x2AC5.into()),
    );
    *gatt_profile.entry_mut(OTS_OACP_CCCD_HANDLE) = GattProfileEntry::ClientCharacteristicConfiguration(0x0);
    gatt_profile.add_characteristic(
        0x0011,
        gatt::GATT_PROP_WRITE | gatt::GATT_PROP_INDICATE,
        OTS_OLCP_HANDLE,
        BluetoothUuid::Uuid16(0x2AC6.into()),
    );
    *gatt_profile.entry_mut(OTS_OLCP_CCCD_HANDLE) = GattProfileEntry::ClientCharacteristicConfiguration(0x0);

    // Characteristic values
    // OTS feature: OACP feature bits [0..9] + OLCP goto feature bit.
    *gatt_profile.entry_mut(OTS_FEATURE_HANDLE) = GattProfileEntry::CharacteristicValue(vec![0xFF, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    *gatt_profile.entry_mut(OTS_NAME_HANDLE) = GattProfileEntry::CharacteristicValue(b"virt-obj".to_vec());
    // OTS Object Type: 16-bit "Unspecified" UUID (0x2ACA).
    *gatt_profile.entry_mut(OTS_TYPE_HANDLE) = GattProfileEntry::CharacteristicValue(0x2ACAu16.to_le_bytes().to_vec());

    let mut size_value = Vec::with_capacity(8);
    size_value.extend_from_slice(&OTS_DEFAULT_CURRENT_SIZE.to_le_bytes());
    size_value.extend_from_slice(&OTS_DEFAULT_ALLOC_SIZE.to_le_bytes());
    *gatt_profile.entry_mut(OTS_SIZE_HANDLE) = GattProfileEntry::CharacteristicValue(size_value);

    *gatt_profile.entry_mut(OTS_ID_HANDLE) = GattProfileEntry::CharacteristicValue(vec![1, 2, 3, 4, 5, 6]);
    *gatt_profile.entry_mut(OTS_PROPERTIES_HANDLE) = GattProfileEntry::CharacteristicValue(vec![0xFF, 0x00, 0x00, 0x00]);
    *gatt_profile.entry_mut(OTS_OACP_HANDLE) = GattProfileEntry::CharacteristicValue(vec![]);
    *gatt_profile.entry_mut(OTS_OLCP_HANDLE) = GattProfileEntry::CharacteristicValue(vec![]);
}

impl OtsEntity {
    pub fn new() -> Self {
        Self {
            pending_oacp_read: None,
            pending_oacp_read_ready: false,
            pending_oacp_write: None,
            object_data: vec![0; OTS_DEFAULT_ALLOC_SIZE as usize],
            object_current_size: OTS_DEFAULT_CURRENT_SIZE,
            object_alloc_size: OTS_DEFAULT_ALLOC_SIZE,
        }
    }

    pub fn take_ready_oacp_read(&mut self) -> Option<(u32, u32)> {
        if self.pending_oacp_read_ready {
            self.pending_oacp_read_ready = false;
            return self.pending_oacp_read.take();
        }
        None
    }

    pub fn read_oacp_object_range(&self, offset: u32, len: u32) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        let start = offset as usize;
        let end = start.saturating_add(len as usize).min(self.object_data.len());
        if start >= end {
            return Vec::new();
        }
        self.object_data[start..end].to_vec()
    }

    pub fn on_oacp_write_sdu(&mut self, payload: &[u8]) -> bool {
        let Some(mut pending) = self.pending_oacp_write else {
            return false;
        };

        let remaining = pending.len.saturating_sub(pending.received) as usize;
        if remaining == 0 {
            self.pending_oacp_write = None;
            return false;
        }

        let to_copy = payload.len().min(remaining);
        let start = pending.offset.saturating_add(pending.received) as usize;
        let end = start.saturating_add(to_copy);
        if end > self.object_data.len() {
            self.object_data.resize(end, 0);
            self.object_alloc_size = self.object_data.len() as u32;
        }

        self.object_data[start..end].copy_from_slice(&payload[..to_copy]);
        pending.received = pending.received.saturating_add(to_copy as u32);
        if pending.received >= pending.len {
            self.object_current_size = self.object_current_size.max(pending.offset.saturating_add(pending.len));
            self.pending_oacp_write = None;
            true
        } else {
            self.pending_oacp_write = Some(pending);
            false
        }
    }

    pub fn on_coc_disconnected(&mut self) {
        self.pending_oacp_read = None;
        self.pending_oacp_read_ready = false;
        self.pending_oacp_write = None;
    }

    pub fn on_handle_value_cfm(&mut self) {
        if self.pending_oacp_read.is_some() {
            self.pending_oacp_read_ready = true;
        }
    }

    pub fn build_oacp_response(&mut self, req: &[u8]) -> Vec<u8> {
        let req_opcode = req.first().copied().unwrap_or(0x00);
        let mut result = OACP_RES_SUCCESS;
        let mut checksum_payload: Option<[u8; 4]> = None;

        match req_opcode {
            // OACP CHECKSUM
            0x03 => {
                if req.len() >= 9 {
                    let offset = u32::from_le_bytes([req[1], req[2], req[3], req[4]]);
                    let len = u32::from_le_bytes([req[5], req[6], req[7], req[8]]);
                    if self.validate_range(offset, len) {
                        let start = offset as usize;
                        let end = start + len as usize;
                        checksum_payload = Some(Self::crc32_ieee(&self.object_data[start..end]).to_le_bytes());
                    } else {
                        result = OACP_RES_INVALID_PARAMETER;
                    }
                } else {
                    result = OACP_RES_INVALID_PARAMETER;
                }
            }
            // OACP READ
            0x05 => {
                if req.len() >= 9 {
                    let offset = u32::from_le_bytes([req[1], req[2], req[3], req[4]]);
                    let len = u32::from_le_bytes([req[5], req[6], req[7], req[8]]);
                    if self.validate_range(offset, len) {
                        self.pending_oacp_read = Some((offset, len));
                        self.pending_oacp_read_ready = false;
                    } else {
                        self.pending_oacp_read = None;
                        self.pending_oacp_read_ready = false;
                        result = OACP_RES_INVALID_PARAMETER;
                    }
                } else {
                    result = OACP_RES_INVALID_PARAMETER;
                }
            }
            // OACP WRITE
            0x06 => {
                if req.len() >= 10 {
                    let offset = u32::from_le_bytes([req[1], req[2], req[3], req[4]]);
                    let len = u32::from_le_bytes([req[5], req[6], req[7], req[8]]);
                    let mode = req[9];
                    if mode == 0x00 && self.validate_write_range(offset, len) {
                        self.pending_oacp_write = Some(PendingOacpWrite { offset, len, received: 0 });
                    } else {
                        self.pending_oacp_write = None;
                        result = OACP_RES_INVALID_PARAMETER;
                    }
                } else {
                    result = OACP_RES_INVALID_PARAMETER;
                }
            }
            _ => {
                result = OACP_RES_OPCODE_NOT_SUPPORTED;
            }
        }

        let mut rsp = vec![0x60, req_opcode, result];
        if result == OACP_RES_SUCCESS {
            if let Some(checksum) = checksum_payload {
                rsp.extend_from_slice(&checksum);
            }
        }
        rsp
    }

    pub fn build_olcp_response(req: &[u8]) -> Vec<u8> {
        let req_opcode = req.first().copied().unwrap_or(0x00);
        // [0x70, request opcode, result code]
        let mut rsp = vec![0x70, req_opcode, 0x01];
        // For REQ_NUM_OBJS (0x07), append object count.
        if req_opcode == 0x07 {
            rsp.extend_from_slice(&1u32.to_le_bytes());
        }
        rsp
    }

    pub fn current_size_value(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8);
        v.extend_from_slice(&self.object_current_size.to_le_bytes());
        v.extend_from_slice(&self.object_alloc_size.to_le_bytes());
        v
    }

    pub fn sync_size_value(&self, profile: &mut GattProfile) {
        *profile.entry_mut(OTS_SIZE_HANDLE) = GattProfileEntry::CharacteristicValue(self.current_size_value());
    }

    fn validate_range(&self, offset: u32, len: u32) -> bool {
        if len == 0 {
            return false;
        }
        let end = offset.saturating_add(len);
        end <= self.object_current_size
    }

    fn validate_write_range(&self, offset: u32, len: u32) -> bool {
        if len == 0 {
            return false;
        }
        let end = offset.saturating_add(len);
        end <= self.object_alloc_size
    }

    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            let mut cur = (crc ^ u32::from(byte)) & 0xFF;
            for _ in 0..8 {
                if (cur & 1) != 0 {
                    cur = (cur >> 1) ^ 0xEDB8_8320;
                } else {
                    cur >>= 1;
                }
            }
            crc = (crc >> 8) ^ cur;
        }
        !crc
    }
}

impl Default for OtsEntity {
    fn default() -> Self {
        Self::new()
    }
}
