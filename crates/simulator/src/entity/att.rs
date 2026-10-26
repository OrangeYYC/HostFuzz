use btuuid::BluetoothUuid;
use deku::prelude::*;
use tracing::{debug, error, warn};

use crate::{
    AttSemanticProbeOrder, PeerGattProfilePreset, Simulator, SimulatorError,
    entity::{
        l2cap::L2capEntity,
        ots::{self, OtsEntity},
    },
};
use ble::{
    att::{AttAttributeData, AttAttributeGroupData, AttErrorCode, AttInformationData, AttPacket},
    gatt::{self, GattAction, GattProfile, GattProfileEntry},
};

fn build_generic_default_peer_gatt_profile() -> GattProfile {
    let mut gatt_profile = GattProfile::blank();

    ots::install_ots_service(&mut gatt_profile);

    // Heart Rate service (0x180D)
    gatt_profile.add_primary_service(0x0020, BluetoothUuid::Uuid16(0x180D.into()), true);
    gatt_profile.add_characteristic(0x0021, gatt::GATT_PROP_NOTIFY, 0x0022, BluetoothUuid::Uuid16(0x2A37.into()));
    *gatt_profile.entry_mut(0x0023) = GattProfileEntry::ClientCharacteristicConfiguration(0x0);

    // Battery service (0x180F)
    gatt_profile.add_primary_service(0x0030, BluetoothUuid::Uuid16(0x180F.into()), true);
    gatt_profile.add_characteristic(
        0x0031,
        gatt::GATT_PROP_READ | gatt::GATT_PROP_NOTIFY,
        0x0032,
        BluetoothUuid::Uuid16(0x2A19.into()),
    );
    *gatt_profile.entry_mut(0x0033) = GattProfileEntry::ClientCharacteristicConfiguration(0x0);

    *gatt_profile.entry_mut(0x0022) = GattProfileEntry::CharacteristicValue(vec![0x00, 0x4B]);
    *gatt_profile.entry_mut(0x0032) = GattProfileEntry::CharacteristicValue(vec![100]);

    gatt_profile
}

fn build_esp_gatts_demo_peer_gatt_profile() -> GattProfile {
    let mut gatt_profile = GattProfile::blank();

    // Profile A: service 0x00FF / char 0xFF01 / CCCD.
    gatt_profile.add_primary_service(0x0028, BluetoothUuid::Uuid16(0x00FF.into()), true);
    gatt_profile.add_characteristic(
        0x0029,
        gatt::GATT_PROP_READ | gatt::GATT_PROP_WRITE | gatt::GATT_PROP_NOTIFY,
        0x002A,
        BluetoothUuid::Uuid16(0xFF01.into()),
    );
    *gatt_profile.entry_mut(0x002A) = GattProfileEntry::CharacteristicValue(vec![0x11, 0x22, 0x33]);
    *gatt_profile.entry_mut(0x002B) = GattProfileEntry::ClientCharacteristicConfiguration(0x0);

    // Profile B: service 0x00EE / char 0xEE01.
    gatt_profile.add_primary_service(0x0030, BluetoothUuid::Uuid16(0x00EE.into()), true);
    gatt_profile.add_characteristic(
        0x0031,
        gatt::GATT_PROP_READ | gatt::GATT_PROP_WRITE,
        0x0032,
        BluetoothUuid::Uuid16(0xEE01.into()),
    );
    *gatt_profile.entry_mut(0x0032) = GattProfileEntry::CharacteristicValue(vec![0x22, 0x33, 0x44]);
    *gatt_profile.entry_mut(0x0033) = GattProfileEntry::CharacteristicUserDescription(String::from("esp-gatts-demo"));

    gatt_profile
}

pub(crate) fn build_peer_gatt_profile(preset: &PeerGattProfilePreset) -> GattProfile {
    match preset {
        PeerGattProfilePreset::GenericDefault => build_generic_default_peer_gatt_profile(),
        PeerGattProfilePreset::EspGattsDemo => build_esp_gatts_demo_peer_gatt_profile(),
    }
}

const HR_MEASUREMENT_HANDLE: u16 = 0x0022;
const HR_MEASUREMENT_CCCD_HANDLE: u16 = 0x0023;
const BAS_LEVEL_HANDLE: u16 = 0x0032;
const BAS_LEVEL_CCCD_HANDLE: u16 = 0x0033;
const UUID_HRS_MEASUREMENT: u16 = 0x2A37;
const UUID_HRS_BODY_SENSOR_LOCATION: u16 = 0x2A38;
const UUID_HRS_CONTROL_POINT: u16 = 0x2A39;
const UUID_BAS_LEVEL: u16 = 0x2A19;
const UUID_MESH_PROV_DATA_IN: u16 = 0x2ADB;
const UUID_MESH_PROXY_DATA_IN: u16 = 0x2ADD;

const MESH_PROXY_MSG_TYPE_NET_PDU: u8 = 0x00;
const MESH_PROXY_MSG_TYPE_PROV: u8 = 0x03;
const MESH_PROXY_SAR_COMPLETE: u8 = 0x00;
const MESH_PROXY_SAR_FIRST: u8 = 0x01;
const MESH_PROXY_SAR_CONT: u8 = 0x02;
const MESH_PROXY_SAR_LAST: u8 = 0x03;
const PASSIVE_WRITE_SWEEP_WIDTH: usize = 6;
const PASSIVE_WRITE_MAX_ROUNDS: u8 = 8;
const PASSIVE_WRITE_ROUND_STRIDE: usize = 5;

pub struct AttEntity<'a> {
    simulator: &'a Simulator,
    conn_handle: u16,
    last_action: GattAction,
    round_finish: bool,
    peer_att_mtu: u16,
    ots: OtsEntity,
    post_discovery_probe_step: u8,
    discovered_hrs_measurement_value_handle: Option<u16>,
    discovered_hrs_measurement_cccd_handle: Option<u16>,
    discovered_hrs_body_sensor_location_handle: Option<u16>,
    discovered_hrs_control_point_handle: Option<u16>,
    discovered_bas_level_handle: Option<u16>,
    discovered_bas_level_cccd_handle: Option<u16>,
    generic_semantic_read_handles: Vec<u16>,
    generic_semantic_write_req_handles: Vec<u16>,
    generic_semantic_write_cmd_handles: Vec<u16>,
    generic_semantic_notify_cccd_handles: Vec<u16>,
    generic_semantic_indicate_cccd_handles: Vec<u16>,
    mesh_semantic_proxy_data_in_handles: Vec<u16>,
    mesh_semantic_prov_data_in_handles: Vec<u16>,
    hr_value: u8,
    bas_value: u8,
    pending_semantic_probe: bool,
    idle_probe_round: u8,
}

impl<'a> AttEntity<'a> {
    pub fn new(simulator: &'a Simulator, conn_handle: u16) -> Self {
        Self {
            simulator,
            conn_handle,
            last_action: GattAction::Unknown,
            round_finish: false,
            peer_att_mtu: 23,
            ots: OtsEntity::new(),
            post_discovery_probe_step: 0,
            discovered_hrs_measurement_value_handle: None,
            discovered_hrs_measurement_cccd_handle: None,
            discovered_hrs_body_sensor_location_handle: None,
            discovered_hrs_control_point_handle: None,
            discovered_bas_level_handle: None,
            discovered_bas_level_cccd_handle: None,
            generic_semantic_read_handles: Vec::new(),
            generic_semantic_write_req_handles: Vec::new(),
            generic_semantic_write_cmd_handles: Vec::new(),
            generic_semantic_notify_cccd_handles: Vec::new(),
            generic_semantic_indicate_cccd_handles: Vec::new(),
            mesh_semantic_proxy_data_in_handles: Vec::new(),
            mesh_semantic_prov_data_in_handles: Vec::new(),
            hr_value: 0x4B,
            bas_value: 100,
            pending_semantic_probe: false,
            idle_probe_round: 0,
        }
    }

    /// parses raw ATT payloads to ATT packet, ignore the invalid packets
    pub fn on_att_raw(&mut self, packet: &[u8]) -> Result<(), SimulatorError> {
        match AttPacket::from_bytes((packet, 0)) {
            Ok(((_, _), att_pkt)) => self.on_att_pkt(att_pkt),
            Err(err) => {
                error!("failed to parse att packet: {}", err);
                error!("invalid packet: {}", hex::encode_upper(packet));
                Err(SimulatorError::TargetCrash)
            }
        }
    }

    /// handle the att protocol packet on server
    fn on_att_pkt(&mut self, packet: AttPacket) -> Result<(), SimulatorError> {
        if self.pending_semantic_probe {
            self.pending_semantic_probe = false;
            if !matches!(&packet, AttPacket::ErrorRsp { .. }) {
                self.simulator.telemetry_mark_semantic_probe_success();
            }
        }
        match &packet {
            AttPacket::ErrorRsp { error_code, .. } => {
                if *error_code == AttErrorCode::AttributeNotFound {
                    match self.last_action {
                        GattAction::PrimaryServiceDiscovery => {
                            self.simulator.target_gatt_profile_mut().finish_discover_all_primary_service();
                            return self.discover_or_interact();
                        }
                        GattAction::IncludedServiceDiscovery(s) => {
                            self.simulator.target_gatt_profile_mut().finish_find_included_service(s);
                            return self.discover_or_interact();
                        }
                        GattAction::CharacteristicDiscovery(s) => {
                            self.simulator.target_gatt_profile_mut().finish_discover_all_characteristic_of_service(s);
                            return self.discover_or_interact();
                        }
                        _ => {}
                    }
                }
                if self.post_discovery_probe_step != 0 && matches!(self.last_action, GattAction::Unknown) {
                    return self.send_next_post_discovery_probe();
                }
                warn!("unhandled ATT packet: {:?}", &packet);
                Ok(())
            }
            AttPacket::ExchangeMtuReq { client_rx_mtu } => self.gatt_req_exchange_mtu(client_rx_mtu),
            AttPacket::ExchangeMtuRsp { server_rx_mtu } => self.gatt_rsp_exchange_mtu(server_rx_mtu),
            AttPacket::ReadByGroupTypeRsp { attribute_data_list, .. } => match self.last_action {
                GattAction::PrimaryServiceDiscovery => self.gatt_rsp_discover_all_primary_service(&attribute_data_list),
                _ => {
                    if self.post_discovery_probe_step != 0 {
                        return self.send_next_post_discovery_probe();
                    }
                    warn!("unhandled ATT packet: {:?}", &packet);
                    Ok(())
                }
            },
            AttPacket::ReadByTypeRsp { attribute_data_list, .. } => match self.last_action {
                GattAction::CharacteristicDiscovery(_) => self.gatt_rsp_discover_all_characteristics_of_service(attribute_data_list),
                _ => {
                    if self.post_discovery_probe_step != 0 {
                        return self.send_next_post_discovery_probe();
                    }
                    warn!("unhandled ATT packet: {:?}", &packet);
                    Ok(())
                }
            },
            AttPacket::FindInformationRsp { .. }
            | AttPacket::FindByTypeValueRsp { .. }
            | AttPacket::ReadRsp { .. }
            | AttPacket::ReadBlobRsp { .. }
            | AttPacket::ReadMultipleRsp { .. }
            | AttPacket::ReadMultipleVariableRsp { .. }
            | AttPacket::WriteRsp
            | AttPacket::PrepareWriteRsp { .. }
            | AttPacket::ExecuteWriteRsp => {
                if self.post_discovery_probe_step != 0 && matches!(self.last_action, GattAction::Unknown) {
                    return self.send_next_post_discovery_probe();
                }
                warn!("unhandled ATT packet: {:?}", &packet);
                Ok(())
            }
            AttPacket::HandleValueInd {
                attribute_handle,
                attribute_value,
            } => {
                debug!("handle ATT_HANDLE_VALUE_IND");
                debug!("  handle=0x{:04x}, value={}", attribute_handle, hex::encode_upper(attribute_value));
                self.write_att_packet(AttPacket::HandleValueCfm)?;

                // The profile may be changed by server, discover again!
                self.simulator.target_gatt_profile_mut().reset();
                self.round_finish = false;
                self.discover_or_interact()
            }
            AttPacket::ReadByGroupTypeReq {
                starting_handle,
                ending_handle,
                attribute_group_type,
            } => {
                // Primary Service Discovery
                if *attribute_group_type == vec![0x00, 0x28] {
                    return self.gatt_req_discover_all_primary_service(*starting_handle, *ending_handle);
                }
                warn!("unhandled ATT packet: {:?}", &packet);
                Ok(())
            }
            AttPacket::ReadByTypeReq {
                starting_handle,
                ending_handle,
                attribute_type,
            } => {
                match attribute_type.as_slice() {
                    [0x02, 0x28] => {
                        // Include Discovery
                        self.gatt_req_discover_included_service(*starting_handle, *ending_handle)
                    }
                    [0x03, 0x28] => {
                        // Characteristic Discovery
                        self.gatt_req_discover_all_characteristic_of_service(*starting_handle, *ending_handle)
                    }
                    _ => {
                        self.write_att_packet(AttPacket::ErrorRsp {
                            request_opcode: 0x08, /* ATT_READ_BY_TYPE_REQ */
                            attribute_handle: *starting_handle,
                            error_code: AttErrorCode::AttributeNotFound,
                        })
                    }
                }
            }
            AttPacket::ReadReq { attribute_handle } => self.gatt_req_read_characteristic_value(*attribute_handle),
            AttPacket::ReadBlobReq {
                attribute_handle,
                value_offset,
            } => self.gatt_req_read_blob_characteristic_value(*attribute_handle, *value_offset),
            AttPacket::ReadMultipleReq { set_of_handlers } => self.gatt_req_read_multiple_characteristic_value(set_of_handlers),
            AttPacket::ReadMultipleVariableReq { set_of_handlers } => self.gatt_req_read_multiple_characteristic_value(set_of_handlers),
            AttPacket::WriteReq {
                attribute_handle,
                attribute_value,
            } => self.gatt_req_write_characteristic_value(*attribute_handle, attribute_value, true),
            AttPacket::WriteCmd {
                attribute_handle,
                attribute_value,
            } => self.gatt_req_write_characteristic_value(*attribute_handle, attribute_value, false),
            AttPacket::SignedWriteCmd {
                attribute_handle,
                attribute_value,
            } => self.gatt_req_write_characteristic_value(*attribute_handle, attribute_value, false),
            AttPacket::PrepareWriteReq { attribute_handle, .. } => self.write_att_packet(AttPacket::ErrorRsp {
                request_opcode: 0x16, /* ATT_PREPARE_WRITE_REQ */
                attribute_handle: *attribute_handle,
                error_code: AttErrorCode::RequestNotSupported,
            }),
            AttPacket::ExecuteWriteReq { .. } => self.write_att_packet(AttPacket::ErrorRsp {
                request_opcode: 0x18, /* ATT_EXECUTE_WRITE_REQ */
                attribute_handle: 0x0000,
                error_code: AttErrorCode::RequestNotSupported,
            }),
            AttPacket::FindInformationReq {
                starting_handle,
                ending_handle,
            } => self.gatt_req_discover_all_characteristic_descriptors(*starting_handle, *ending_handle),
            AttPacket::FindByTypeValueReq {
                starting_handle,
                ending_handle,
                attribute_type,
                attribute_value,
            } => self.gatt_req_find_by_type_value(*starting_handle, *ending_handle, *attribute_type, attribute_value),
            AttPacket::HandleValueCfm => {
                self.on_handle_value_cfm();
                Ok(())
            }
            AttPacket::HandleValueNtf {
                attribute_handle,
                attribute_value,
            } => {
                debug!("handle ATT_HANDLE_VALUE_NTF");
                debug!("  handle=0x{:04x}, value={}", attribute_handle, hex::encode_upper(attribute_value));
                Ok(())
            }
            pkt => {
                warn!("unhandled ATT packet: {:?}", pkt);
                Ok(())
            }
        }
    }

    pub fn initiate_interact(&mut self) {
        if self.simulator.ablation_flags().enable_semantic_probe_generation {
            self.discover_or_interact().unwrap();
        } else {
            self.do_interact().unwrap();
        }
    }

    /// Re-runs discovery/interaction after link security changes (for example, after pairing
    /// completed) so P3 can revisit security-gated attributes with the negotiated link state.
    pub fn restart_after_security_refresh(&mut self) -> Result<(), SimulatorError> {
        self.last_action = GattAction::Unknown;
        self.round_finish = false;
        self.post_discovery_probe_step = 0;
        self.pending_semantic_probe = false;
        self.idle_probe_round = 0;
        self.clear_semantic_handles();
        self.simulator.target_gatt_profile_mut().reset();
        self.discover_or_interact()
    }

    /// Returns pending OACP read request (offset, length) when confirmed by ATT Handle Value Confirmation.
    pub fn take_ready_oacp_read(&mut self) -> Option<(u32, u32)> {
        self.ots.take_ready_oacp_read()
    }

    pub fn read_oacp_object_range(&self, offset: u32, len: u32) -> Vec<u8> {
        self.ots.read_oacp_object_range(offset, len)
    }

    pub fn on_oacp_write_sdu(&mut self, payload: &[u8]) {
        if self.ots.on_oacp_write_sdu(payload) {
            let mut profile = self.simulator.peer_gatt_profile_mut();
            self.ots.sync_size_value(&mut profile);
        }
    }

    pub fn on_oacp_coc_disconnected(&mut self) {
        self.ots.on_coc_disconnected();
    }

    /// write att packet to the host
    fn write_att_packet(&self, packet: AttPacket) -> Result<(), SimulatorError> {
        let data = packet.to_bytes().unwrap();
        self.simulator.send_l2cap_bframe(self.conn_handle, L2capEntity::CID_ATT, data)?;
        Ok(())
    }

    /// Handles request of GATT exchange MTU. Server MTU is set to the same with Client MTU.
    fn gatt_req_exchange_mtu(&mut self, client_rx_mtu: &u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] exchange MTU (ATT_EXCHANGE_MTU_REQ)");
        debug!("  client_rx_mtu=0x{:04x}", client_rx_mtu);

        self.last_action = GattAction::Unknown;
        self.peer_att_mtu = *client_rx_mtu;
        self.simulator.target_gatt_profile_mut().mtu = Some(*client_rx_mtu);
        self.write_att_packet(AttPacket::ExchangeMtuRsp { server_rx_mtu: *client_rx_mtu })
    }

    /// Handles response of GATT exchange MTU.
    fn gatt_rsp_exchange_mtu(&mut self, server_rx_mtu: &u16) -> Result<(), SimulatorError> {
        debug!("[GATT RSP] exchange MTU (ATT_EXCHANGE_MTU_RSP)");
        debug!("  server_rx_mtu=0x{:04x}", server_rx_mtu);

        self.peer_att_mtu = *server_rx_mtu;
        self.simulator.target_gatt_profile_mut().mtu = Some(*server_rx_mtu);
        self.discover_or_interact()
    }

    /// Sends one ATT Write Command like Zephyr `peripheral_gatt_write` sample.
    pub fn send_stream_write_cmd(&self) -> Result<(), SimulatorError> {
        let payload_len = usize::from(self.peer_att_mtu.saturating_sub(3).max(1));
        self.write_att_packet(AttPacket::WriteCmd {
            attribute_handle: 0x0001,
            attribute_value: vec![0x00; payload_len],
        })
    }

    /// Handles request of GATT discovery all primary service.
    fn gatt_req_discover_all_primary_service(&mut self, start: u16, end: u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] discover all primary service (ATT_READ_BY_GROUP_TYPE_REQ)");
        debug!("   in: start=0x{:04x}, end=0x{:04x}", start, end);

        let mut profile = self.simulator.peer_gatt_profile_mut();
        match profile.get_primary_service_range(start, end) {
            Some((length, attribute_data)) => {
                debug!(
                    "  out: handle=0x{:04x}, end=0x{:04x}, uuid={}",
                    attribute_data.attribute_handle,
                    attribute_data.end_group_handle,
                    hex::encode_upper(&attribute_data.attribute_value)
                );
                self.write_att_packet(AttPacket::ReadByGroupTypeRsp {
                    length,
                    attribute_data_list: vec![attribute_data],
                })
            }
            None => {
                debug!("  out: attribute not found");
                self.write_att_packet(AttPacket::ErrorRsp {
                    request_opcode: 0x10, /*ATT_READ_BY_GROUP_TYPE_REQ*/
                    attribute_handle: start,
                    error_code: AttErrorCode::AttributeNotFound,
                })
            }
        }
    }

    /// Handles response of GATT discovery all primary service.
    fn gatt_rsp_discover_all_primary_service(&mut self, attribute_data_list: &Vec<AttAttributeGroupData>) -> Result<(), SimulatorError> {
        debug!("[GATT RSP] discover all primary service (ATT_READ_BY_GROUP_TYPE_RSP)");

        for (i, group) in attribute_data_list.iter().enumerate() {
            debug!(
                "  [{}] handle=0x{:04x}, end=0x{:04x}, uuid={}",
                i,
                group.attribute_handle,
                group.end_group_handle,
                hex::encode_upper(&group.attribute_value)
            );

            if let Ok(uuid) = BluetoothUuid::from_le_slice(&group.attribute_value[..]) {
                self.simulator
                    .target_gatt_profile_mut()
                    .add_primary_service(group.attribute_handle, uuid, false);

                // if this group ends at 0xffff, we finishes the discovery of primary service
                if group.end_group_handle == 0xffff {
                    self.simulator.target_gatt_profile_mut().finish_discover_all_primary_service();
                }
            } else {
                warn!("get invalid bluetooth uuid");
            }
        }
        self.discover_or_interact()
    }

    /// Handles request of GATT discovery included service.
    fn gatt_req_discover_included_service(&mut self, start: u16, end: u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] discover included service (ATT_READ_BY_TYPE_REQ)");
        debug!("   in: start=0x{:04x}, end=0x{:04x}", start, end);

        let mut profile = self.simulator.peer_gatt_profile_mut();
        match profile.get_included_service_range(start, end) {
            Some((length, attribute_data)) => {
                debug!(
                    "  out: handle=0x{:04x}, payload={}",
                    attribute_data.attribute_handle,
                    hex::encode_upper(&attribute_data.attribute_value)
                );
                self.write_att_packet(AttPacket::ReadByTypeRsp {
                    length,
                    attribute_data_list: vec![attribute_data],
                })
            }
            None => {
                debug!("  out: attribute not found");
                self.write_att_packet(AttPacket::ErrorRsp {
                    request_opcode: 0x08, /* ATT_READ_BY_TYPE_REQ */
                    attribute_handle: start,
                    error_code: AttErrorCode::AttributeNotFound,
                })
            }
        }
    }

    /// Handles request of GATT discovery all characteristics of a service.
    fn gatt_req_discover_all_characteristic_of_service(&mut self, start: u16, end: u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] discover all characteristics of a service (ATT_READ_BY_TYPE_REQ)");
        debug!("   in: start=0x{:04x}, end=0x{:04x}", start, end);

        let mut profile = self.simulator.peer_gatt_profile_mut();
        match profile.get_characteristic_range(start, end) {
            Some((handle, decl)) => {
                debug!("  out: handle=0x{:04x}, characteristic={}", handle, decl);
                let attribute_value: Vec<u8> = decl.into();
                self.write_att_packet(AttPacket::ReadByTypeRsp {
                    length: 0x2 + attribute_value.len() as u8,
                    attribute_data_list: vec![AttAttributeData {
                        attribute_handle: *handle,
                        attribute_value,
                    }],
                })
            }
            None => {
                debug!("  out: attribute not found");
                self.write_att_packet(AttPacket::ErrorRsp {
                    request_opcode: 0x08, /* ATT_READ_BY_TYPE_REQ */
                    attribute_handle: start,
                    error_code: AttErrorCode::AttributeNotFound,
                })
            }
        }
    }

    /// Handles response of GATT discovery all characteristics of a service.
    fn gatt_rsp_discover_all_characteristics_of_service(&mut self, attribute_data_list: &Vec<AttAttributeData>) -> Result<(), SimulatorError> {
        debug!("[GATT RSP] discover all characteristic of a service (ATT_READ_BY_TYPE_RSP)");

        for (id, entry) in attribute_data_list.iter().enumerate() {
            if entry.attribute_value.len() < 3 {
                continue;
            }
            let property = entry.attribute_value[0];
            let value_handle = u16::from_le_bytes(entry.attribute_value[1..3].try_into().unwrap());
            if let Ok(uuid) = BluetoothUuid::from_le_slice(&entry.attribute_value[3..]) {
                debug!(
                    "  [{}] characteristic: property=0x{:x} value_handle=0x{:x} uuid={}",
                    id,
                    property,
                    value_handle,
                    uuid.to_string()
                );

                self.simulator
                    .target_gatt_profile_mut()
                    .add_characteristic(entry.attribute_handle, property, value_handle, uuid);
            }
        }
        self.discover_or_interact()
    }

    /// Handles request of GATT discovery all characteristics descriptors.
    fn gatt_req_discover_all_characteristic_descriptors(&mut self, start: u16, end: u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] discover all characteristics descriptors (ATT_FIND_INFORMATION_REQ)");
        debug!("   in: start=0x{:04x}, end=0x{:04x}", start, end);

        let mut profile = self.simulator.peer_gatt_profile_mut();
        match profile.get_characteristic_descriptor_range(start, end) {
            Some((handle, BluetoothUuid::Uuid16(uuid))) => {
                debug!("  out: handle=0x{:04x}, uuid={}", handle, uuid.to_string());
                self.write_att_packet(AttPacket::FindInformationRsp {
                    information: AttInformationData::Bit16Uuid(vec![(*handle, uuid.to_u16())]),
                })
            }
            Some((handle, BluetoothUuid::Uuid128(uuid))) => {
                debug!("  out: handle=0x{:04x}, uuid={}", handle, uuid.to_string());
                self.write_att_packet(AttPacket::FindInformationRsp {
                    information: AttInformationData::Bit128Uuid(vec![(*handle, uuid.to_u128())]),
                })
            }
            _ => {
                debug!("  out: attribute not found");
                self.write_att_packet(AttPacket::ErrorRsp {
                    request_opcode: 0x04, /* ATT_FIND_INFORMATION_REQ */
                    attribute_handle: start,
                    error_code: AttErrorCode::AttributeNotFound,
                })
            }
        }
    }

    /// Handles request of GATT find by type value.
    ///
    /// This is mainly used by central-side stacks to discover a specific primary service UUID.
    fn gatt_req_find_by_type_value(&mut self, start: u16, end: u16, attribute_type: u16, attribute_value: &[u8]) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] find by type value (ATT_FIND_BY_TYPE_VALUE_REQ)");
        debug!(
            "   in: start=0x{:04x}, end=0x{:04x}, attribute_type=0x{:04x}, value={}",
            start,
            end,
            attribute_type,
            hex::encode_upper(attribute_value)
        );

        // ATT_FIND_BY_TYPE_VALUE_REQ is only used for 16-bit UUIDs.
        if attribute_value.len() != 2 || attribute_type != 0x2800 {
            self.write_att_packet(AttPacket::ErrorRsp {
                request_opcode: 0x06, /* ATT_FIND_BY_TYPE_VALUE_REQ */
                attribute_handle: start,
                error_code: AttErrorCode::AttributeNotFound,
            })?;
            return Ok(());
        }

        let profile = self.simulator.peer_gatt_profile();
        let mut handles_information_list = Vec::new();
        for handle in start..=end {
            match profile.entry(handle) {
                GattProfileEntry::PrimaryService(service) if service.uuid.as_le_slice() == attribute_value => {
                    let end_group_handle = profile.service_group_end(handle);
                    handles_information_list.push((handle, end_group_handle));
                }
                _ => {}
            }
        }

        if handles_information_list.is_empty() {
            debug!("  out: attribute not found");
            self.write_att_packet(AttPacket::ErrorRsp {
                request_opcode: 0x06, /* ATT_FIND_BY_TYPE_VALUE_REQ */
                attribute_handle: start,
                error_code: AttErrorCode::AttributeNotFound,
            })?;
        } else {
            debug!("  out: {} matched service(s)", handles_information_list.len());
            self.write_att_packet(AttPacket::FindByTypeValueRsp { handles_information_list })?;
        }
        Ok(())
    }

    /// Handles request of GATT read characteristic value.
    fn gatt_req_read_characteristic_value(&mut self, handle: u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] read characteristic value (ATT_READ_REQ)");
        debug!("   in: handle=0x{:04x}", handle);

        if handle == ots::OTS_SIZE_HANDLE {
            return self.write_att_packet(AttPacket::ReadRsp {
                attribute_value: self.ots.current_size_value(),
            });
        }

        let profile = self.simulator.peer_gatt_profile();
        let entry = profile.entry(handle);
        match entry {
            GattProfileEntry::CharacteristicValue(value_entry) => self.write_att_packet(AttPacket::ReadRsp {
                attribute_value: value_entry.clone(),
            }),
            GattProfileEntry::ClientCharacteristicConfiguration(value) => self.write_att_packet(AttPacket::ReadRsp {
                attribute_value: vec![*value, 0x00],
            }),
            GattProfileEntry::Unknown => {
                warn!("reading unknown GATT profile entry, reply with fake value");
                self.write_att_packet(AttPacket::ReadRsp {
                    attribute_value: vec![0x12, 0x34],
                })
            }
            _ => self.write_att_packet(AttPacket::ErrorRsp {
                request_opcode: 0x0A, /* ATT_READ_REQ */
                attribute_handle: handle,
                error_code: AttErrorCode::ReadNotPermitted,
            }),
        }
    }

    fn gatt_req_read_blob_characteristic_value(&mut self, handle: u16, value_offset: u16) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] read blob characteristic value (ATT_READ_BLOB_REQ)");
        debug!("   in: handle=0x{:04x}, offset=0x{:04x}", handle, value_offset);

        let mut attribute_value = if handle == ots::OTS_SIZE_HANDLE {
            self.ots.current_size_value()
        } else {
            let profile = self.simulator.peer_gatt_profile();
            match profile.entry(handle) {
                GattProfileEntry::CharacteristicValue(v) => v.clone(),
                GattProfileEntry::ClientCharacteristicConfiguration(v) => vec![*v, 0x00],
                GattProfileEntry::Unknown => {
                    return self.write_att_packet(AttPacket::ErrorRsp {
                        request_opcode: 0x0C, /* ATT_READ_BLOB_REQ */
                        attribute_handle: handle,
                        error_code: AttErrorCode::InvalidHandle,
                    });
                }
                _ => {
                    return self.write_att_packet(AttPacket::ErrorRsp {
                        request_opcode: 0x0C, /* ATT_READ_BLOB_REQ */
                        attribute_handle: handle,
                        error_code: AttErrorCode::ReadNotPermitted,
                    });
                }
            }
        };

        let offset = usize::from(value_offset);
        if offset > attribute_value.len() {
            return self.write_att_packet(AttPacket::ErrorRsp {
                request_opcode: 0x0C, /* ATT_READ_BLOB_REQ */
                attribute_handle: handle,
                error_code: AttErrorCode::InvalidOffset,
            });
        }
        let partial = attribute_value.split_off(offset);
        self.write_att_packet(AttPacket::ReadBlobRsp { part_attribute_value: partial })
    }

    fn gatt_req_read_multiple_characteristic_value(&mut self, handles: &[u16]) -> Result<(), SimulatorError> {
        debug!("[GATT REQ] read multiple characteristic value (ATT_READ_MULTIPLE_REQ)");
        debug!("   in: handles={:?}", handles);

        let profile = self.simulator.peer_gatt_profile();
        let mut set_of_values = Vec::new();
        for handle in handles {
            match profile.entry(*handle) {
                GattProfileEntry::CharacteristicValue(v) => set_of_values.extend_from_slice(v),
                GattProfileEntry::ClientCharacteristicConfiguration(v) => set_of_values.extend_from_slice(&[*v, 0x00]),
                _ => {
                    return self.write_att_packet(AttPacket::ErrorRsp {
                        request_opcode: 0x0E, /* ATT_READ_MULTIPLE_REQ */
                        attribute_handle: *handle,
                        error_code: AttErrorCode::InvalidHandle,
                    });
                }
            }
        }
        self.write_att_packet(AttPacket::ReadMultipleRsp { set_of_values })
    }

    /// Handles request/cmd of GATT write characteristic value.
    fn gatt_req_write_characteristic_value(&mut self, handle: u16, value: &[u8], with_rsp: bool) -> Result<(), SimulatorError> {
        debug!(
            "[GATT REQ] write characteristic value (ATT_{})",
            if with_rsp { "WRITE_REQ" } else { "WRITE_CMD" }
        );
        debug!("   in: handle=0x{:04x}, value={}", handle, hex::encode_upper(value));

        let mut profile = self.simulator.peer_gatt_profile_mut();
        let mut pending_oacp_rsp: Option<Vec<u8>> = None;
        let mut pending_olcp_rsp: Option<Vec<u8>> = None;
        let mut pending_notifications: Vec<(u16, Vec<u8>)> = Vec::new();

        let write_result = match profile.entry_mut(handle) {
            GattProfileEntry::ClientCharacteristicConfiguration(cccd) => {
                if value.len() != 2 {
                    Err(AttErrorCode::InvalidAttributeValueLength)
                } else {
                    let cccd_value = u16::from_le_bytes([value[0], value[1]]);
                    *cccd = (cccd_value & 0x00FF) as u8;

                    if handle == HR_MEASUREMENT_CCCD_HANDLE && (cccd_value & ots::GATT_CCCD_NOTIFY) == ots::GATT_CCCD_NOTIFY {
                        let hr = self.next_hr_value();
                        if let GattProfileEntry::CharacteristicValue(v) = profile.entry_mut(HR_MEASUREMENT_HANDLE) {
                            v.clear();
                            // Flags + HR Measurement Value
                            v.extend_from_slice(&[0x00, hr]);
                        }
                        pending_notifications.push((HR_MEASUREMENT_HANDLE, vec![0x00, hr]));
                    }

                    if handle == BAS_LEVEL_CCCD_HANDLE && (cccd_value & ots::GATT_CCCD_NOTIFY) == ots::GATT_CCCD_NOTIFY {
                        let bas = self.next_bas_value();
                        if let GattProfileEntry::CharacteristicValue(v) = profile.entry_mut(BAS_LEVEL_HANDLE) {
                            v.clear();
                            v.push(bas);
                        }
                        pending_notifications.push((BAS_LEVEL_HANDLE, vec![bas]));
                    }
                    Ok(())
                }
            }
            GattProfileEntry::CharacteristicValue(v) => {
                v.clear();
                v.extend_from_slice(value);

                if handle == ots::OTS_OACP_HANDLE {
                    pending_oacp_rsp = Some(self.ots.build_oacp_response(value));
                } else if handle == ots::OTS_OLCP_HANDLE {
                    pending_olcp_rsp = Some(OtsEntity::build_olcp_response(value));
                }
                Ok(())
            }
            GattProfileEntry::Unknown => Err(AttErrorCode::InvalidHandle),
            _ => Err(AttErrorCode::WriteNotPermitted),
        };
        drop(profile);

        if let Err(error_code) = write_result {
            if with_rsp {
                self.write_att_packet(AttPacket::ErrorRsp {
                    request_opcode: 0x12, /* ATT_WRITE_REQ */
                    attribute_handle: handle,
                    error_code,
                })?;
            }
            return Ok(());
        }

        if with_rsp {
            self.write_att_packet(AttPacket::WriteRsp)?;
        }

        for (notify_handle, notify_value) in pending_notifications {
            self.write_att_packet(AttPacket::HandleValueNtf {
                attribute_handle: notify_handle,
                attribute_value: notify_value,
            })?;
        }

        if let Some(rsp) = pending_oacp_rsp {
            let profile = self.simulator.peer_gatt_profile();
            if Self::cccd_indicate_enabled(&profile, ots::OTS_OACP_CCCD_HANDLE) {
                drop(profile);
                self.write_att_packet(AttPacket::HandleValueInd {
                    attribute_handle: ots::OTS_OACP_HANDLE,
                    attribute_value: rsp,
                })?;
            }
        }
        if let Some(rsp) = pending_olcp_rsp {
            let profile = self.simulator.peer_gatt_profile();
            if Self::cccd_indicate_enabled(&profile, ots::OTS_OLCP_CCCD_HANDLE) {
                drop(profile);
                self.write_att_packet(AttPacket::HandleValueInd {
                    attribute_handle: ots::OTS_OLCP_HANDLE,
                    attribute_value: rsp,
                })?;
            }
        }
        Ok(())
    }

    #[inline]
    fn cccd_indicate_enabled(profile: &GattProfile, cccd_handle: u16) -> bool {
        matches!(
            profile.entry(cccd_handle),
            GattProfileEntry::ClientCharacteristicConfiguration(v)
                if (u16::from(*v) & ots::GATT_CCCD_INDICATE) == ots::GATT_CCCD_INDICATE
        )
    }

    #[inline]
    fn next_hr_value(&mut self) -> u8 {
        self.hr_value = self.hr_value.saturating_add(1);
        if self.hr_value >= 160 {
            self.hr_value = 90;
        }
        self.hr_value
    }

    #[inline]
    fn next_bas_value(&mut self) -> u8 {
        if self.bas_value == 0 {
            self.bas_value = 100;
        } else {
            self.bas_value = self.bas_value.saturating_sub(1);
        }
        self.bas_value
    }

    fn on_handle_value_cfm(&mut self) {
        self.ots.on_handle_value_cfm();
    }

    /// Chooses to discovery feature or interact with the target.
    pub fn discover_or_interact(&mut self) -> Result<(), SimulatorError> {
        // Keep RefCell borrow scope tight, otherwise calling do_interact() on the None
        // branch may try to re-borrow target_gatt_profile and panic.
        let next_action = { self.simulator.target_gatt_profile_mut().next_discovery_action() };
        match next_action {
            None => {
                self.last_action = GattAction::Unknown;
                self.simulator.telemetry_mark_discovery_completed();
                self.do_interact()
            }
            Some((act, packet)) => {
                self.last_action = act;
                self.simulator.telemetry_mark_discovery_started();
                self.write_att_packet(packet)
            }
        }
    }

    /// Interacts with the target.
    pub fn do_interact(&mut self) -> Result<(), SimulatorError> {
        debug!("choose to interact with the packet");
        if self.round_finish {
            return Ok(());
        }
        // We only do one interact with the target since the fuzzer can generate different
        // interaction behavior.
        self.round_finish = true;
        if self.simulator.ablation_flags().enable_runtime_profile_feedback || self.simulator.ablation_flags().enable_semantic_probe_generation {
            self.refresh_semantic_handles_from_target_profile();
        } else {
            self.clear_semantic_handles();
        }
        if self.simulator.ablation_flags().enable_semantic_probe_generation && self.send_mesh_sar_burst_probes()? {
            self.simulator.telemetry_mark_semantic_interaction_started();
            self.simulator.telemetry_mark_semantic_probe_sent();
            self.simulator.telemetry_mark_semantic_probe_success();
        }
        self.post_discovery_probe_step = 1;
        self.send_next_post_discovery_probe()
    }

    /// In passive-server scenarios, proactively seed write-command traffic even when discovery
    /// has discovered concrete write handles, so fuzzing can explore data-ingress handlers
    /// without sending blind early writes.
    pub fn bootstrap_passive_server_interact(&mut self) -> Result<bool, SimulatorError> {
        if !self.has_discovered_passive_write_handles() {
            return Ok(false);
        }
        self.send_passive_write_sweep()
    }

    /// Called by the controller idle driver to keep write-oriented ATT interaction alive when
    /// the host stops producing HCI commands.
    pub fn on_idle_tick(&mut self) -> Result<bool, SimulatorError> {
        if !self.simulator.ablation_flags().enable_semantic_probe_generation {
            return Ok(false);
        }
        if !self.has_discovered_passive_write_handles() {
            return Ok(false);
        }
        self.send_passive_write_sweep()
    }

    fn has_discovered_passive_write_handles(&self) -> bool {
        if !self.mesh_semantic_prov_data_in_handles.is_empty()
            || !self.mesh_semantic_proxy_data_in_handles.is_empty()
            || !self.generic_semantic_write_cmd_handles.is_empty()
            || !self.generic_semantic_write_req_handles.is_empty()
        {
            return true;
        }

        let profile = self.simulator.target_gatt_profile();
        for known in profile.known_handles() {
            let GattProfileEntry::CharacteristicDeclaration(decl) = profile.entry(known) else {
                continue;
            };
            if (decl.property & (gatt::GATT_PROP_WRITE | gatt::GATT_PROP_WRITE_WITHOUT_RESP)) != 0 {
                return true;
            }
        }
        false
    }

    fn send_passive_write_sweep(&mut self) -> Result<bool, SimulatorError> {
        if self.idle_probe_round >= PASSIVE_WRITE_MAX_ROUNDS {
            return Ok(false);
        }

        let handles = self.collect_passive_write_handles();
        if handles.is_empty() {
            return Ok(false);
        }

        let start = (usize::from(self.idle_probe_round) * PASSIVE_WRITE_ROUND_STRIDE) % handles.len();
        let width = PASSIVE_WRITE_SWEEP_WIDTH.min(handles.len());
        for offset in 0..width {
            let handle = handles[(start + offset) % handles.len()];
            let marker = self.idle_probe_round.wrapping_mul(PASSIVE_WRITE_SWEEP_WIDTH as u8).wrapping_add(offset as u8);
            let sar = marker & 0x03;
            let msg_type = if (marker & 0x01) == 0 {
                MESH_PROXY_MSG_TYPE_PROV
            } else {
                MESH_PROXY_MSG_TYPE_NET_PDU
            };
            let payload = self.passive_probe_payload(handle, sar, msg_type, marker);
            self.write_att_packet(AttPacket::WriteCmd {
                attribute_handle: handle,
                attribute_value: payload,
            })?;
        }

        self.idle_probe_round = self.idle_probe_round.saturating_add(1);
        self.pending_semantic_probe = false;
        self.simulator.telemetry_mark_semantic_interaction_started();
        self.simulator.telemetry_mark_semantic_probe_sent();
        self.simulator.telemetry_mark_semantic_probe_success();
        Ok(true)
    }

    fn collect_passive_write_handles(&self) -> Vec<u16> {
        let mut handles = Vec::new();

        for handle in &self.mesh_semantic_prov_data_in_handles {
            Self::push_passive_handle(&mut handles, *handle);
        }
        for handle in &self.mesh_semantic_proxy_data_in_handles {
            Self::push_passive_handle(&mut handles, *handle);
        }
        for handle in &self.generic_semantic_write_cmd_handles {
            Self::push_passive_handle(&mut handles, *handle);
        }
        for handle in &self.generic_semantic_write_req_handles {
            Self::push_passive_handle(&mut handles, *handle);
        }

        if handles.is_empty() {
            let profile = self.simulator.target_gatt_profile();
            for known in profile.known_handles() {
                let GattProfileEntry::CharacteristicDeclaration(decl) = profile.entry(known) else {
                    continue;
                };
                if (decl.property & (gatt::GATT_PROP_WRITE | gatt::GATT_PROP_WRITE_WITHOUT_RESP)) == 0 {
                    continue;
                }
                Self::push_passive_handle(&mut handles, decl.value_handle);
            }
        }

        handles
    }

    fn passive_probe_payload(&self, handle: u16, sar: u8, msg_type: u8, marker: u8) -> Vec<u8> {
        let mut payload = self.semantic_write_payload(handle);
        let target_len = 8usize.saturating_add((marker as usize) % 16);

        if payload.is_empty() {
            payload.push(0);
        }
        if payload.len() < target_len {
            let seed = (handle as u8).wrapping_mul(13).wrapping_add(marker.wrapping_mul(17));
            for idx in payload.len()..target_len {
                payload.push(seed.wrapping_add(idx as u8));
            }
        }
        payload[0] = Self::mesh_proxy_header(sar, msg_type);
        payload
    }

    fn send_next_post_discovery_probe(&mut self) -> Result<(), SimulatorError> {
        if self.simulator.ablation_flags().enable_semantic_probe_generation
            && self.post_discovery_probe_step > self.simulator.max_att_profile_guided_probe_steps()
        {
            self.post_discovery_probe_step = 0;
            self.pending_semantic_probe = false;
            return Ok(());
        }

        let (packet, is_semantic) = if self.simulator.ablation_flags().enable_semantic_probe_generation {
            self.profile_guided_probe_packet()
        } else {
            (self.generic_probe_packet(self.post_discovery_probe_step), false)
        };

        let Some(packet) = packet else {
            self.post_discovery_probe_step = 0;
            return Ok(());
        };
        self.post_discovery_probe_step = self.post_discovery_probe_step.saturating_add(1);
        if is_semantic {
            self.simulator.telemetry_mark_semantic_interaction_started();
            self.simulator.telemetry_mark_semantic_probe_sent();
            self.pending_semantic_probe = true;
        } else {
            self.pending_semantic_probe = false;
        }
        self.write_att_packet(packet)
    }

    fn profile_guided_probe_packet(&self) -> (Option<AttPacket>, bool) {
        let mut step_cursor = 1u8;
        if let Some(cccd_handle) = self.discovered_hrs_measurement_cccd_handle {
            if self.post_discovery_probe_step == step_cursor {
                debug!("semantic HRS probe: enable measurement notification on cccd=0x{:04x}", cccd_handle);
                return (
                    Some(AttPacket::WriteReq {
                        attribute_handle: cccd_handle,
                        attribute_value: vec![0x01, 0x00],
                    }),
                    true,
                );
            }
            step_cursor = step_cursor.saturating_add(1);
        }
        self.semantic_or_generic_probe_packet(step_cursor)
    }

    fn semantic_or_generic_probe_packet(&self, mut step_cursor: u8) -> (Option<AttPacket>, bool) {
        if let Some(handle) = self.discovered_hrs_body_sensor_location_handle {
            if self.post_discovery_probe_step == step_cursor {
                debug!("semantic HRS probe: read body sensor location handle=0x{:04x}", handle);
                return (Some(AttPacket::ReadReq { attribute_handle: handle }), true);
            }
            step_cursor = step_cursor.saturating_add(1);
        }

        if let Some(handle) = self.discovered_hrs_control_point_handle {
            if self.post_discovery_probe_step == step_cursor {
                debug!("semantic HRS probe: write control point handle=0x{:04x}", handle);
                return (
                    Some(AttPacket::WriteReq {
                        attribute_handle: handle,
                        attribute_value: vec![0x01], // Reset Energy Expended
                    }),
                    true,
                );
            }
            step_cursor = step_cursor.saturating_add(1);
        }

        if let Some(handle) = self.discovered_bas_level_handle {
            if self.post_discovery_probe_step == step_cursor {
                debug!("semantic BAS probe: read battery level handle=0x{:04x}", handle);
                return (Some(AttPacket::ReadReq { attribute_handle: handle }), true);
            }
            step_cursor = step_cursor.saturating_add(1);
        }

        if let Some(cccd_handle) = self.discovered_bas_level_cccd_handle {
            if self.post_discovery_probe_step == step_cursor {
                debug!("semantic BAS probe: enable battery notification on cccd=0x{:04x}", cccd_handle);
                return (
                    Some(AttPacket::WriteReq {
                        attribute_handle: cccd_handle,
                        attribute_value: vec![0x01, 0x00],
                    }),
                    true,
                );
            }
            step_cursor = step_cursor.saturating_add(1);
        }

        let profile_probe_step = usize::from(self.post_discovery_probe_step.saturating_sub(step_cursor));
        if let Some(packet) = self.generic_profile_probe_packet(profile_probe_step) {
            return (Some(packet), true);
        }
        (None, false)
    }

    fn generic_probe_packet(&self, generic_step: u8) -> Option<AttPacket> {
        match generic_step {
            // Legacy generic probes retained as fallback.
            1 => Some(AttPacket::ReadReq { attribute_handle: 0x000B }),
            2 => Some(AttPacket::ReadBlobReq {
                attribute_handle: 0x000B,
                value_offset: 1,
            }),
            3 => Some(AttPacket::FindInformationReq {
                starting_handle: 0x0001,
                ending_handle: 0x0010,
            }),
            4 => Some(AttPacket::ReadByTypeReq {
                starting_handle: 0x0001,
                ending_handle: 0x0010,
                attribute_type: vec![0x03, 0x28],
            }),
            5 => Some(AttPacket::WriteReq {
                attribute_handle: 0x0004,
                attribute_value: vec![0x02, 0x00],
            }),
            6 => Some(AttPacket::PrepareWriteReq {
                attribute_handle: 0x0004,
                value_offset: 0,
                part_attribute_value: vec![0x01],
            }),
            7 => Some(AttPacket::ExecuteWriteReq { flags: 0x01 }),
            8 => Some(AttPacket::WriteReq {
                attribute_handle: 0x2AA6,
                attribute_value: vec![0x12, 0x34, 0x56, 0x78],
            }),
            _ => None,
        }
    }

    fn send_mesh_sar_burst_probes(&self) -> Result<bool, SimulatorError> {
        let mut sent = false;

        for handle in &self.mesh_semantic_prov_data_in_handles {
            debug!("semantic mesh probe: SAR burst to prov data-in handle=0x{:04x}", handle);
            self.send_mesh_sar_sequence(*handle, MESH_PROXY_MSG_TYPE_PROV)?;
            sent = true;
        }
        for handle in &self.mesh_semantic_proxy_data_in_handles {
            debug!("semantic mesh probe: SAR burst to proxy data-in handle=0x{:04x}", handle);
            self.send_mesh_sar_sequence(*handle, MESH_PROXY_MSG_TYPE_NET_PDU)?;
            sent = true;
        }

        Ok(sent)
    }

    fn send_mesh_sar_sequence(&self, handle: u16, msg_type: u8) -> Result<(), SimulatorError> {
        let att_payload_cap = usize::from(self.peer_att_mtu.saturating_sub(3).max(8));
        let body_len = att_payload_cap.saturating_sub(1).clamp(7, 96);
        let tail_body_len = (body_len / 2).max(4).min(body_len);
        let cont_fragments = 4usize;

        // Seed one complete frame first, then segmented FIRST/CONT/LAST sequence to exercise
        // both single-frame and SAR reassembly code paths in mesh data ingress.
        self.write_att_packet(self.mesh_write_cmd_packet(
            handle,
            MESH_PROXY_SAR_COMPLETE,
            msg_type,
            0,
            body_len,
        ))?;
        self.write_att_packet(self.mesh_write_cmd_packet(
            handle,
            MESH_PROXY_SAR_FIRST,
            msg_type,
            1,
            body_len,
        ))?;
        for idx in 0..cont_fragments {
            self.write_att_packet(self.mesh_write_cmd_packet(
                handle,
                MESH_PROXY_SAR_CONT,
                msg_type,
                2u8.saturating_add(idx as u8),
                body_len,
            ))?;
        }
        self.write_att_packet(self.mesh_write_cmd_packet(
            handle,
            MESH_PROXY_SAR_LAST,
            msg_type,
            2u8.saturating_add(cont_fragments as u8),
            tail_body_len,
        ))?;
        Ok(())
    }

    fn mesh_write_cmd_packet(&self, handle: u16, sar: u8, msg_type: u8, fragment_idx: u8, body_len: usize) -> AttPacket {
        AttPacket::WriteCmd {
            attribute_handle: handle,
            attribute_value: Self::mesh_proxy_payload(handle, sar, msg_type, fragment_idx, body_len),
        }
    }

    fn mesh_proxy_payload(handle: u16, sar: u8, msg_type: u8, fragment_idx: u8, body_len: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(body_len.saturating_add(1));
        payload.push(Self::mesh_proxy_header(sar, msg_type));

        let seed = (handle as u8).wrapping_mul(17).wrapping_add(fragment_idx.wrapping_mul(29));
        for idx in 0..body_len {
            payload.push(seed.wrapping_add(idx as u8));
        }
        payload
    }

    #[inline]
    fn mesh_proxy_header(sar: u8, msg_type: u8) -> u8 {
        ((sar & 0x03) << 6) | (msg_type & 0x3f)
    }

    fn clear_semantic_handles(&mut self) {
        self.discovered_hrs_measurement_value_handle = None;
        self.discovered_hrs_measurement_cccd_handle = None;
        self.discovered_hrs_body_sensor_location_handle = None;
        self.discovered_hrs_control_point_handle = None;
        self.discovered_bas_level_handle = None;
        self.discovered_bas_level_cccd_handle = None;
        self.generic_semantic_read_handles.clear();
        self.generic_semantic_write_req_handles.clear();
        self.generic_semantic_write_cmd_handles.clear();
        self.generic_semantic_notify_cccd_handles.clear();
        self.generic_semantic_indicate_cccd_handles.clear();
        self.mesh_semantic_proxy_data_in_handles.clear();
        self.mesh_semantic_prov_data_in_handles.clear();
    }

    fn refresh_semantic_handles_from_target_profile(&mut self) {
        self.clear_semantic_handles();

        let profile = self.simulator.target_gatt_profile();
        let known_handles = profile.known_handles();

        for handle in &known_handles {
            let GattProfileEntry::CharacteristicDeclaration(decl) = profile.entry(*handle) else {
                continue;
            };

            if Self::uuid16_eq(&decl.uuid, UUID_HRS_MEASUREMENT) {
                self.discovered_hrs_measurement_value_handle = Some(decl.value_handle);
                if (decl.property & gatt::GATT_PROP_NOTIFY) != 0 {
                    self.discovered_hrs_measurement_cccd_handle = decl.value_handle.checked_add(1);
                }
                continue;
            }

            if Self::uuid16_eq(&decl.uuid, UUID_HRS_BODY_SENSOR_LOCATION) {
                self.discovered_hrs_body_sensor_location_handle = Some(decl.value_handle);
                continue;
            }

            if Self::uuid16_eq(&decl.uuid, UUID_HRS_CONTROL_POINT) {
                self.discovered_hrs_control_point_handle = Some(decl.value_handle);
                continue;
            }

            if Self::uuid16_eq(&decl.uuid, UUID_BAS_LEVEL) {
                self.discovered_bas_level_handle = Some(decl.value_handle);
                if (decl.property & gatt::GATT_PROP_NOTIFY) != 0 {
                    self.discovered_bas_level_cccd_handle = decl.value_handle.checked_add(1);
                }
            }

            if (decl.property & gatt::GATT_PROP_WRITE_WITHOUT_RESP) != 0 {
                if Self::uuid16_eq(&decl.uuid, UUID_MESH_PROXY_DATA_IN) {
                    Self::push_mesh_semantic_handle(&mut self.mesh_semantic_proxy_data_in_handles, decl.value_handle);
                } else if Self::uuid16_eq(&decl.uuid, UUID_MESH_PROV_DATA_IN) {
                    Self::push_mesh_semantic_handle(&mut self.mesh_semantic_prov_data_in_handles, decl.value_handle);
                }
            }

            if (decl.property & gatt::GATT_PROP_READ) != 0 {
                Self::push_semantic_handle(&mut self.generic_semantic_read_handles, decl.value_handle);
            }
            if (decl.property & (gatt::GATT_PROP_WRITE | gatt::GATT_PROP_AUTH_WRITE)) != 0 {
                Self::push_semantic_handle(&mut self.generic_semantic_write_req_handles, decl.value_handle);
            } else if (decl.property & gatt::GATT_PROP_WRITE_WITHOUT_RESP) != 0 {
                Self::push_semantic_handle(&mut self.generic_semantic_write_cmd_handles, decl.value_handle);
            }
            if (decl.property & gatt::GATT_PROP_NOTIFY) != 0 {
                if let Some(cccd_handle) = decl.value_handle.checked_add(1) {
                    Self::push_semantic_handle(&mut self.generic_semantic_notify_cccd_handles, cccd_handle);
                }
            }
            if (decl.property & gatt::GATT_PROP_INDICATE) != 0 {
                if let Some(cccd_handle) = decl.value_handle.checked_add(1) {
                    Self::push_semantic_handle(&mut self.generic_semantic_indicate_cccd_handles, cccd_handle);
                }
            }
        }

        // Fallback extraction helps P3 on cases where discovery only recovers value/descriptor
        // entries but not enough declaration semantics for targeted probes.
        for handle in known_handles {
            match profile.entry(handle) {
                GattProfileEntry::CharacteristicValue(value)
                    if !value.is_empty()
                        && !self.generic_semantic_read_handles.contains(&handle)
                        && !self.generic_semantic_write_req_handles.contains(&handle)
                        && !self.generic_semantic_write_cmd_handles.contains(&handle) =>
                {
                    Self::push_semantic_handle(&mut self.generic_semantic_read_handles, handle);
                }
                GattProfileEntry::ClientCharacteristicConfiguration(_) => {
                    if self.discovered_hrs_measurement_cccd_handle.is_none() {
                        self.discovered_hrs_measurement_cccd_handle = Some(handle);
                    } else if self.discovered_bas_level_cccd_handle.is_none() {
                        self.discovered_bas_level_cccd_handle = Some(handle);
                    }
                    Self::push_semantic_handle(&mut self.generic_semantic_notify_cccd_handles, handle);
                    Self::push_semantic_handle(&mut self.generic_semantic_indicate_cccd_handles, handle);
                }
                _ => {}
            }
        }

        debug!(
            "semantic handles: hrs_meas={:?}, hrs_cccd={:?}, hrs_bsl={:?}, hrs_cp={:?}, bas={:?}, bas_cccd={:?}, mesh_proxy_data_in={:?}, mesh_prov_data_in={:?}, generic_read={:?}, generic_write_req={:?}, generic_write_cmd={:?}, generic_notify={:?}, generic_indicate={:?}",
            self.discovered_hrs_measurement_value_handle,
            self.discovered_hrs_measurement_cccd_handle,
            self.discovered_hrs_body_sensor_location_handle,
            self.discovered_hrs_control_point_handle,
            self.discovered_bas_level_handle,
            self.discovered_bas_level_cccd_handle,
            &self.mesh_semantic_proxy_data_in_handles,
            &self.mesh_semantic_prov_data_in_handles,
            &self.generic_semantic_read_handles,
            &self.generic_semantic_write_req_handles,
            &self.generic_semantic_write_cmd_handles,
            &self.generic_semantic_notify_cccd_handles,
            &self.generic_semantic_indicate_cccd_handles
        );
    }

    fn push_semantic_handle(handles: &mut Vec<u16>, handle: u16) {
        const MAX_GENERIC_SEMANTIC_HANDLES: usize = 6;

        if handles.contains(&handle) || handles.len() >= MAX_GENERIC_SEMANTIC_HANDLES {
            return;
        }
        handles.push(handle);
        handles.sort_unstable();
    }

    fn push_mesh_semantic_handle(handles: &mut Vec<u16>, handle: u16) {
        const MAX_MESH_SEMANTIC_HANDLES: usize = 4;

        if handles.contains(&handle) || handles.len() >= MAX_MESH_SEMANTIC_HANDLES {
            return;
        }
        handles.push(handle);
        handles.sort_unstable();
    }

    fn push_passive_handle(handles: &mut Vec<u16>, handle: u16) {
        const MAX_PASSIVE_HANDLES: usize = 24;

        if handles.contains(&handle) || handles.len() >= MAX_PASSIVE_HANDLES {
            return;
        }
        handles.push(handle);
        handles.sort_unstable();
    }

    fn generic_profile_probe_packet(&self, index: usize) -> Option<AttPacket> {
        match self.simulator.att_semantic_probe_order() {
            AttSemanticProbeOrder::ReadFirst => self.generic_profile_probe_packet_read_first(index),
            AttSemanticProbeOrder::WriteFirst => self.generic_profile_probe_packet_write_first(index),
        }
    }

    fn generic_profile_probe_packet_read_first(&self, mut index: usize) -> Option<AttPacket> {
        let read_steps = self.generic_semantic_read_handles.len().saturating_mul(2);
        if index < read_steps {
            let handle = self.generic_semantic_read_handles[index / 2];
            if index % 2 == 0 {
                debug!("semantic generic probe: read handle=0x{:04x}", handle);
                return Some(Self::read_req_packet(handle));
            }
            debug!("semantic generic probe: read blob handle=0x{:04x}", handle);
            return Some(Self::read_blob_packet(handle));
        }
        index = index.saturating_sub(read_steps);

        let write_req_steps = self.generic_semantic_write_req_handles.len().saturating_mul(2);
        if index < write_req_steps {
            let handle = self.generic_semantic_write_req_handles[index / 2];
            if index % 2 == 0 {
                debug!("semantic generic probe: write req handle=0x{:04x}", handle);
                return Some(self.write_req_packet(handle));
            }
            debug!("semantic generic probe: prepare write handle=0x{:04x}", handle);
            return Some(self.prepare_write_packet(handle));
        }
        index = index.saturating_sub(write_req_steps);

        if !self.generic_semantic_write_req_handles.is_empty() {
            if index == 0 {
                debug!("semantic generic probe: execute write");
                return Some(AttPacket::ExecuteWriteReq { flags: 0x01 });
            }
            index = index.saturating_sub(1);
        }

        if index < self.generic_semantic_write_cmd_handles.len() {
            let handle = self.generic_semantic_write_cmd_handles[index];
            debug!("semantic generic probe: write cmd handle=0x{:04x}", handle);
            return Some(self.write_cmd_packet(handle));
        }
        index = index.saturating_sub(self.generic_semantic_write_cmd_handles.len());

        let notify_steps = self.generic_semantic_notify_cccd_handles.len().saturating_mul(2);
        if index < notify_steps {
            let handle = self.generic_semantic_notify_cccd_handles[index / 2];
            let enable = index % 2 == 0;
            debug!(
                "semantic generic probe: {} notify on cccd=0x{:04x}",
                if enable { "enable" } else { "disable" },
                handle
            );
            return Some(Self::cccd_write_packet(handle, if enable { 0x0001 } else { 0x0000 }));
        }
        index = index.saturating_sub(notify_steps);

        let indicate_steps = self.generic_semantic_indicate_cccd_handles.len().saturating_mul(2);
        if index < indicate_steps {
            let handle = self.generic_semantic_indicate_cccd_handles[index / 2];
            let enable = index % 2 == 0;
            debug!(
                "semantic generic probe: {} indicate on cccd=0x{:04x}",
                if enable { "enable" } else { "disable" },
                handle
            );
            return Some(Self::cccd_write_packet(handle, if enable { 0x0002 } else { 0x0000 }));
        }

        None
    }

    fn generic_profile_probe_packet_write_first(&self, mut index: usize) -> Option<AttPacket> {
        let write_req_steps = self.generic_semantic_write_req_handles.len().saturating_mul(2);
        if index < write_req_steps {
            let handle = Self::probe_handle_from_back(&self.generic_semantic_write_req_handles, index / 2)?;
            if index % 2 == 0 {
                debug!("semantic generic probe: write req handle=0x{:04x}", handle);
                return Some(self.write_req_packet(handle));
            }
            debug!("semantic generic probe: prepare write handle=0x{:04x}", handle);
            return Some(self.prepare_write_packet(handle));
        }
        index = index.saturating_sub(write_req_steps);

        if !self.generic_semantic_write_req_handles.is_empty() {
            if index == 0 {
                debug!("semantic generic probe: execute write");
                return Some(AttPacket::ExecuteWriteReq { flags: 0x01 });
            }
            index = index.saturating_sub(1);
        }

        let notify_steps = self.generic_semantic_notify_cccd_handles.len().saturating_mul(2);
        if index < notify_steps {
            let handle = Self::probe_handle_from_back(&self.generic_semantic_notify_cccd_handles, index / 2)?;
            let enable = index % 2 == 0;
            debug!(
                "semantic generic probe: {} notify on cccd=0x{:04x}",
                if enable { "enable" } else { "disable" },
                handle
            );
            return Some(Self::cccd_write_packet(handle, if enable { 0x0001 } else { 0x0000 }));
        }
        index = index.saturating_sub(notify_steps);

        let indicate_steps = self.generic_semantic_indicate_cccd_handles.len().saturating_mul(2);
        if index < indicate_steps {
            let handle = Self::probe_handle_from_back(&self.generic_semantic_indicate_cccd_handles, index / 2)?;
            let enable = index % 2 == 0;
            debug!(
                "semantic generic probe: {} indicate on cccd=0x{:04x}",
                if enable { "enable" } else { "disable" },
                handle
            );
            return Some(Self::cccd_write_packet(handle, if enable { 0x0002 } else { 0x0000 }));
        }
        index = index.saturating_sub(indicate_steps);

        if index < self.generic_semantic_write_cmd_handles.len() {
            let handle = Self::probe_handle_from_back(&self.generic_semantic_write_cmd_handles, index)?;
            debug!("semantic generic probe: write cmd handle=0x{:04x}", handle);
            return Some(self.write_cmd_packet(handle));
        }
        index = index.saturating_sub(self.generic_semantic_write_cmd_handles.len());

        let read_steps = self.generic_semantic_read_handles.len().saturating_mul(2);
        if index < read_steps {
            let handle = Self::probe_handle_from_back(&self.generic_semantic_read_handles, index / 2)?;
            if index % 2 == 0 {
                debug!("semantic generic probe: read handle=0x{:04x}", handle);
                return Some(Self::read_req_packet(handle));
            }
            debug!("semantic generic probe: read blob handle=0x{:04x}", handle);
            return Some(Self::read_blob_packet(handle));
        }

        None
    }

    fn probe_handle_from_back(handles: &[u16], ordinal: usize) -> Option<u16> {
        handles.len().checked_sub(ordinal + 1).map(|idx| handles[idx])
    }

    fn read_req_packet(handle: u16) -> AttPacket {
        AttPacket::ReadReq { attribute_handle: handle }
    }

    fn read_blob_packet(handle: u16) -> AttPacket {
        AttPacket::ReadBlobReq {
            attribute_handle: handle,
            value_offset: 1,
        }
    }

    fn write_req_packet(&self, handle: u16) -> AttPacket {
        AttPacket::WriteReq {
            attribute_handle: handle,
            attribute_value: self.semantic_write_payload(handle),
        }
    }

    fn prepare_write_packet(&self, handle: u16) -> AttPacket {
        let payload = self.semantic_write_payload(handle);
        AttPacket::PrepareWriteReq {
            attribute_handle: handle,
            value_offset: 0,
            part_attribute_value: payload[..payload.len().min(4)].to_vec(),
        }
    }

    fn write_cmd_packet(&self, handle: u16) -> AttPacket {
        AttPacket::WriteCmd {
            attribute_handle: handle,
            attribute_value: self.semantic_write_payload(handle),
        }
    }

    fn cccd_write_packet(handle: u16, value: u16) -> AttPacket {
        AttPacket::WriteReq {
            attribute_handle: handle,
            attribute_value: value.to_le_bytes().to_vec(),
        }
    }

    fn semantic_write_payload(&self, handle: u16) -> Vec<u8> {
        if self.mesh_semantic_prov_data_in_handles.contains(&handle) {
            return Self::mesh_proxy_payload(handle, MESH_PROXY_SAR_COMPLETE, MESH_PROXY_MSG_TYPE_PROV, 0, 8);
        }
        if self.mesh_semantic_proxy_data_in_handles.contains(&handle) {
            return Self::mesh_proxy_payload(handle, MESH_PROXY_SAR_COMPLETE, MESH_PROXY_MSG_TYPE_NET_PDU, 0, 8);
        }
        match handle {
            ots::OTS_OACP_HANDLE => {
                let mut payload = vec![0x05];
                payload.extend_from_slice(&0u32.to_le_bytes());
                payload.extend_from_slice(&0x10u32.to_le_bytes());
                payload
            }
            ots::OTS_OLCP_HANDLE => vec![0x07, 0x01],
            _ => vec![0x01, (handle & 0x00ff) as u8, (handle >> 8) as u8],
        }
    }

    #[inline]
    fn uuid16_eq(uuid: &BluetoothUuid, expected: u16) -> bool {
        let bytes = uuid.as_le_slice();
        bytes.len() == 2 && bytes[0] == (expected & 0x00ff) as u8 && bytes[1] == (expected >> 8) as u8
    }
}
