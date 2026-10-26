use ble::hci::{ControllerToHostPacket, HciPacket, HostToControllerPacket};
use deku::DekuContainerWrite;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{cell::RefCell, io::Write};

pub struct PcapDumper {
    enabled: bool,
    packets: RefCell<Vec<(u32, u32, HciPacket)>>,
}

impl PcapDumper {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            packets: RefCell::new(Vec::new()),
        }
    }

    pub fn host_to_controller(&self, packet: &HostToControllerPacket) {
        if self.enabled {
            self.push_packet(HciPacket::HostToController(packet.clone()));
        }
    }

    pub fn controller_to_host(&self, packet: &ControllerToHostPacket) {
        if self.enabled {
            self.push_packet(HciPacket::ControllerToHost(packet.clone()));
        }
    }

    fn push_packet(&self, packet: HciPacket) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards");

        let ts_sec: u32 = now.as_secs() as u32;
        let ts_usec: u32 = now.subsec_micros();

        self.packets.borrow_mut().push((ts_sec, ts_usec, packet));
    }

    pub fn dump(&self, file: &str) {
        let mut file = std::fs::File::create(file).expect("failed to create dump file");
        file.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, // magic
            0x02, 0x00, 0x04, 0x00, // version 2.4
            0, 0, 0, 0, // thiszone
            0, 0, 0, 0, // sigfigs
            0xff, 0xff, 0x00, 0x00, // snaplen
            201, 0x00, 0x0, 0x0, // LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
        ])
        .unwrap();

        for packet in self.packets.borrow().iter() {
            let (ts_sec, ts_usec, direction, mut raw) = match packet {
                (a, b, HciPacket::ControllerToHost(p)) => (a, b, 0x0, p.to_bytes().expect("invalid hci packet")),
                (a, b, HciPacket::HostToController(p)) => (a, b, 0x1, p.to_bytes().expect("invalid hci packet")),
            };

            // pcap record header
            file.write_all(&ts_sec.to_le_bytes()).unwrap();
            file.write_all(&ts_usec.to_le_bytes()).unwrap();
            file.write_all(&(raw.len() as u32 + 4).to_le_bytes()).unwrap();
            file.write_all(&(raw.len() as u32 + 4).to_le_bytes()).unwrap();

            // pseudo header
            file.write_all(&[
                direction, 0x00, 0x00, 0x00, // reserved
            ])
            .unwrap();

            // fix command param length
            if raw[0] == 0x01 {
                raw[3] = raw.len() as u8 - 4
            }

            // H4 packet
            file.write_all(&raw).unwrap();
        }
    }
}
