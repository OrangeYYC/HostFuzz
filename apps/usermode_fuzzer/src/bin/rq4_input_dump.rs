use std::env;

use ble::{
    hci::{
        ControllerToHostPacket, HciEventPkt,
        event::{LeMetaEventBody, LeAdvertisingReportEvent, LeExtendedAdvertisingReportEvent},
    },
    input::MetaInput,
};
use libafl::inputs::Input;

const EXT_ADV_REPORT_FIXED_PREFIX_LEN: usize = 24;
const PBADV_AD_TYPE: u8 = 0x29;

fn parse_pbadv_summary_from_adv_data(data: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    while offset < data.len() {
        let ad_len = data[offset] as usize;
        if ad_len == 0 {
            break;
        }
        let ad_end = offset + 1 + ad_len;
        if ad_end > data.len() {
            break;
        }
        if ad_len >= 2 && data[offset + 1] == PBADV_AD_TYPE {
            let payload = &data[(offset + 2)..ad_end];
            if payload.len() >= 6 {
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let txn = payload[4];
                let gpcf = payload[5] & 0x03;
                let seg = payload[5] >> 2;
                if gpcf == 0x03 && payload.len() >= 22 {
                    let uuid = &payload[6..22];
                    return Some(format!(
                        "pbadv(link=0x{link_id:08x},txn=0x{txn:02x},gpcf=link_open,seg={seg},uuid={})",
                        hex::encode(uuid)
                    ));
                }
                if gpcf == 0x00 && payload.len() >= 10 {
                    let msg_len = u16::from_be_bytes([payload[6], payload[7]]);
                    let fcs = payload[8];
                    return Some(format!(
                        "pbadv(link=0x{link_id:08x},txn=0x{txn:02x},gpcf=tx_start,seg={seg},msg_len={msg_len},fcs=0x{fcs:02x},copy_len={})",
                        payload.len().saturating_sub(9)
                    ));
                }
                return Some(format!(
                    "pbadv(link=0x{link_id:08x},txn=0x{txn:02x},gpcf=0x{gpcf:02x},seg={seg},payload_len={})",
                    payload.len()
                ));
            }
        }
        offset = ad_end;
    }
    None
}

fn summarize_adv_data(data: &[u8]) -> String {
    let first = data.first().copied().unwrap_or(0);
    if let Some(pbadv) = parse_pbadv_summary_from_adv_data(data) {
        format!("len={},first=0x{first:02x},{pbadv}", data.len())
    } else {
        format!("len={},first=0x{first:02x}", data.len())
    }
}

fn describe_adv_report(body: &LeAdvertisingReportEvent) -> String {
    let mut parts = Vec::new();
    for (idx, r) in body.reports.iter().enumerate() {
        parts.push(format!(
            "#{idx}:evt=0x{:02x},{}",
            r.event_type,
            summarize_adv_data(&r.data)
        ));
    }
    parts.join(";")
}

fn describe_ext_adv_report(body: &LeExtendedAdvertisingReportEvent) -> String {
    let len = body.payload.len();
    let first = body.payload.first().copied().unwrap_or(0);
    if len < EXT_ADV_REPORT_FIXED_PREFIX_LEN {
        return format!("payload_len={len},first=0x{first:02x}");
    }
    let data_len_idx = EXT_ADV_REPORT_FIXED_PREFIX_LEN - 1;
    let declared_len = body.payload[data_len_idx] as usize;
    let available_len = len - EXT_ADV_REPORT_FIXED_PREFIX_LEN;
    let adv_len = declared_len.min(available_len);
    let adv_data = &body.payload[EXT_ADV_REPORT_FIXED_PREFIX_LEN..(EXT_ADV_REPORT_FIXED_PREFIX_LEN + adv_len)];
    if let Some(pbadv) = parse_pbadv_summary_from_adv_data(adv_data) {
        format!("payload_len={len},first=0x{first:02x},adv_len={adv_len},{pbadv}")
    } else {
        format!("payload_len={len},first=0x{first:02x},adv_len={adv_len}")
    }
}

fn describe_packet(packet: &ControllerToHostPacket) -> String {
    match packet {
        ControllerToHostPacket::AclData(pkt) => {
            let first = pkt.data.first().copied().unwrap_or(0);
            format!("AclData(len={},first=0x{first:02x})", pkt.data_total_length)
        }
        ControllerToHostPacket::SyncData(pkt) => {
            format!("SyncData(len={})", pkt.data_total_length)
        }
        ControllerToHostPacket::IsoData(pkt) => {
            format!("IsoData(len={})", pkt.data_total_length)
        }
        ControllerToHostPacket::Event(HciEventPkt::LeMata(le)) => match &le.body {
            LeMetaEventBody::AdvertisingReport(body) => {
                format!("LeMeta::AdvertisingReport({})", describe_adv_report(body))
            }
            LeMetaEventBody::ExtendedAdvertisingReport(body) => {
                format!("LeMeta::ExtendedAdvertisingReport({})", describe_ext_adv_report(body))
            }
            other => format!("LeMeta::{other:?}"),
        },
        ControllerToHostPacket::Event(evt) => format!("Event::{evt:?}"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: rq4_input_dump <meta_input.bin>");
        std::process::exit(2);
    }
    let path = &args[1];
    let input = MetaInput::from_file(path).expect("failed to load input");
    println!("file={path}");
    println!("mutate_start={}", input.mutate_start());
    println!("phases={}", input.phases().len());
    for (phase_idx, phase) in input.phases().iter().enumerate() {
        println!("phase[{phase_idx}] packets={}", phase.len());
        for (pkt_idx, pkt) in phase.iter().enumerate() {
            println!("  [{pkt_idx}] {}", describe_packet(pkt));
        }
    }
}
