use std::{env, process};

use ble::{
    hci::{
        ControllerToHostPacket, HciEventPkt,
        event::{AdvertisingReport, LeExtendedAdvertisingReportEvent, LeMetaEventBody},
    },
    input::MetaInput,
};
use libafl::inputs::Input;

fn legacy_adv_report_to_extended_payload(report: &AdvertisingReport) -> Vec<u8> {
    let data_len = report.data.len().min(191).min(usize::from(u8::MAX));
    let mut payload = vec![0u8; 24 + data_len];

    // Legacy-event mapping used by BTstack LE Extended Advertising Report handler.
    // For PB-ADV we keep non-connectable legacy event type (0x10).
    let ext_event_type = match report.event_type {
        0x00 => 0x13u16,
        0x01 => 0x15u16,
        0x02 => 0x12u16,
        0x04 => 0x1Au16,
        _ => 0x10u16,
    };
    payload[0..2].copy_from_slice(&ext_event_type.to_le_bytes());
    payload[2] = report.address_type as u8;
    payload[3..9].copy_from_slice(&report.address.addr);
    payload[9] = 0x01; // primary PHY: LE 1M
    payload[10] = 0x00; // secondary PHY
    payload[11] = 0x00; // advertising sid
    payload[12] = 0x00; // tx power
    payload[13] = report.rssi;
    payload[14] = 0x00; // periodic interval
    payload[15] = 0x00;
    payload[16] = 0x00; // direct address type
    payload[17..23].fill(0x00); // direct address
    payload[23] = data_len as u8;
    payload[24..(24 + data_len)].copy_from_slice(&report.data[..data_len]);
    payload
}

fn is_pb_adv_start_candidate(report: &AdvertisingReport) -> bool {
    report.event_type == 0x03
        && report.data.len() > 31
        && report.data.get(1).copied() == Some(0x29)
        && (report.data.get(7).copied().unwrap_or(0) & 0x03) == 0x00
}

fn patch_bt03_pb_adv_oversize(input: &mut MetaInput) -> bool {
    for phase in input.phases_mut().iter_mut() {
        for packet in phase.iter_mut() {
            let ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta)) = packet else {
                continue;
            };
            let LeMetaEventBody::AdvertisingReport(report_evt) = &mut le_meta.body else {
                continue;
            };
            if report_evt.reports.is_empty() {
                continue;
            }

            let target = &mut report_evt.reports[0];
            target.event_type = 0x03; // non-connectable ADV

            // PB-ADV overlong start packet candidate:
            // data[0] = length, data[1] = AD type 0x29 (PB-ADV), data[7] lower 2 bits = GPCF start.
            let adv_len = 180usize;
            let mut data = vec![0u8; adv_len + 1];
            data[0] = adv_len as u8;
            data[1] = 0x29;
            // link_id
            data[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            // transaction number
            data[6] = 0x01;
            // generic provisioning control: last_segment=0, format=start (bits[1:0]=0)
            data[7] = 0x00;
            // msg_len (<= 158 to pass existing check)
            data[8] = 0x00;
            data[9] = 0x20;
            // fcs
            data[10] = 0x5A;
            for (i, b) in data.iter_mut().enumerate().skip(11) {
                *b = (i & 0xFF) as u8;
            }

            target.data = data;
            target.data_length = target.data.len().min(usize::from(u8::MAX)) as u8;

            if report_evt.reports.len() > 1 {
                // Keep secondary reports harmless to avoid masking the intended first-report path.
                let secondary = &mut report_evt.reports[1];
                secondary.event_type = 0x04;
                secondary.data = vec![0x0A, 0x09, 0x56, 0x69, 0x72, 0x74, 0x42, 0x4C, 0x45, 0x2D, 0x50];
                secondary.data_length = secondary.data.len() as u8;
            }
            return true;
        }
    }
    false
}

fn patch_bt03_pb_adv_link_open_then_start(input: &mut MetaInput) -> bool {
    const MESH_UUID: [u8; 16] = [0xB8, 0x10, 0x45, 0x54, 0xB7, 0xC7, 0xDF, 0x62, 0x01, 0x7D, 0x70, 0xE8, 0x46, 0xEB, 0x47, 0x32];
    const LINK_ID: [u8; 4] = [0x01, 0x23, 0x45, 0x67];

    for phase in input.phases_mut().iter_mut() {
        for packet in phase.iter_mut() {
            let ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta)) = packet else {
                continue;
            };
            let LeMetaEventBody::AdvertisingReport(report_evt) = &mut le_meta.body else {
                continue;
            };
            if report_evt.reports.len() < 2 {
                continue;
            }

            let report_open = &mut report_evt.reports[0];
            report_open.event_type = 0x03;
            report_open.data = vec![0u8; 24];
            report_open.data[0] = 23;
            report_open.data[1] = 0x29;
            report_open.data[2..6].copy_from_slice(&LINK_ID);
            report_open.data[6] = 0x00;
            report_open.data[7] = 0x03;
            report_open.data[8..24].copy_from_slice(&MESH_UUID);
            report_open.data_length = report_open.data.len().min(usize::from(u8::MAX)) as u8;

            let report_start = &mut report_evt.reports[1];
            report_start.event_type = 0x03;
            let adv_len = 180usize;
            let mut data = vec![0u8; adv_len + 1];
            data[0] = adv_len as u8;
            data[1] = 0x29;
            data[2..6].copy_from_slice(&LINK_ID);
            data[6] = 0x01;
            data[7] = 0x00;
            data[8] = 0x00;
            data[9] = 0x20;
            data[10] = 0x5A;
            for (i, b) in data.iter_mut().enumerate().skip(11) {
                *b = (i & 0xFF) as u8;
            }
            report_start.data = data;
            report_start.data_length = report_start.data.len().min(usize::from(u8::MAX)) as u8;
            return true;
        }
    }
    false
}

fn patch_bt03_pb_adv_link_open_then_later_start(input: &mut MetaInput) -> bool {
    const MESH_UUID: [u8; 16] = [0xB8, 0x10, 0x45, 0x54, 0xB7, 0xC7, 0xDF, 0x62, 0x01, 0x7D, 0x70, 0xE8, 0x46, 0xEB, 0x47, 0x32];
    const LINK_ID: [u8; 4] = [0x01, 0x23, 0x45, 0x67];
    let mut start_packet: Option<ControllerToHostPacket> = None;
    let mut anchor_phase: Option<usize> = None;

    for (phase_idx, phase) in input.phases_mut().iter_mut().enumerate() {
        for packet in phase.iter_mut() {
            let ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta)) = packet else {
                continue;
            };
            let le_meta_snapshot = le_meta.clone();
            let LeMetaEventBody::AdvertisingReport(report_evt) = &mut le_meta.body else {
                continue;
            };
            if report_evt.reports.is_empty() || anchor_phase.is_some() {
                continue;
            }

            // First adv report -> LINK_OPEN.
            let report_open = &mut report_evt.reports[0];
            report_open.event_type = 0x03;
            report_open.data = vec![0u8; 24];
            report_open.data[0] = 23;
            report_open.data[1] = 0x29;
            report_open.data[2..6].copy_from_slice(&LINK_ID);
            report_open.data[6] = 0x00;
            report_open.data[7] = 0x03;
            report_open.data[8..24].copy_from_slice(&MESH_UUID);
            report_open.data_length = report_open.data.len().min(usize::from(u8::MAX)) as u8;

            if report_evt.reports.len() > 1 {
                let secondary = &mut report_evt.reports[1];
                secondary.event_type = 0x04;
                secondary.data = vec![0x0A, 0x09, 0x56, 0x69, 0x72, 0x74, 0x42, 0x4C, 0x45, 0x2D, 0x50];
                secondary.data_length = secondary.data.len() as u8;
            }

            // Build a later TRANSACTION_START packet to send in a subsequent phase.
            let mut start_meta = le_meta_snapshot;
            let mut start_evt = report_evt.clone();
            start_evt.reports.truncate(1);
            let report_start = &mut start_evt.reports[0];
            report_start.event_type = 0x03;
            let adv_len = 180usize;
            let mut data = vec![0u8; adv_len + 1];
            data[0] = adv_len as u8;
            data[1] = 0x29;
            data[2..6].copy_from_slice(&LINK_ID);
            data[6] = 0x01;
            data[7] = 0x00;
            data[8] = 0x00;
            data[9] = 0x20;
            data[10] = 0x5A;
            for (i, b) in data.iter_mut().enumerate().skip(11) {
                *b = (i & 0xFF) as u8;
            }
            report_start.data = data;
            report_start.data_length = report_start.data.len().min(usize::from(u8::MAX)) as u8;
            start_meta.body = LeMetaEventBody::AdvertisingReport(start_evt);
            start_packet = Some(ControllerToHostPacket::Event(HciEventPkt::LeMata(start_meta)));
            anchor_phase = Some(phase_idx);
            break;
        }
        if anchor_phase.is_some() {
            break;
        }
    }

    let Some(anchor_phase) = anchor_phase else {
        return false;
    };
    let Some(start_packet) = start_packet else {
        return false;
    };

    // Prefer appending TRANSACTION_START in the first post-anchor phase that already
    // carries a ConnectionComplete event. This creates a meaningful delay while keeping
    // the packet on an executed path.
    for (phase_idx, phase) in input.phases_mut().iter_mut().enumerate() {
        if phase_idx <= anchor_phase {
            continue;
        }
        let has_conn_complete = phase.iter().any(|packet| {
            matches!(
                packet,
                ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta))
                    if matches!(le_meta.body, LeMetaEventBody::ConnectionComplete(_))
            )
        });
        if has_conn_complete {
            phase.push(start_packet.clone());
            return true;
        }
    }

    // Secondary choice: append after a later scan-enable failure
    // (0x2006 status=0x0C), which is typically tens of milliseconds after LINK_OPEN.
    for (phase_idx, phase) in input.phases_mut().iter_mut().enumerate() {
        if phase_idx <= anchor_phase {
            continue;
        }
        for packet in phase.iter() {
            let ControllerToHostPacket::Event(HciEventPkt::CommandComplete(cmd)) = packet else {
                continue;
            };
            let status = cmd.return_parameters.first().copied().unwrap_or(0);
            if cmd.command_opcode == 0x2006 && status == 0x0C {
                phase.push(start_packet.clone());
                return true;
            }
        }
    }

    // Secondary choice: append after the second 0x200A command-complete.
    let mut cc_200a_seen = 0usize;
    for (phase_idx, phase) in input.phases_mut().iter_mut().enumerate() {
        if phase_idx <= anchor_phase {
            continue;
        }
        for packet in phase.iter() {
            let ControllerToHostPacket::Event(HciEventPkt::CommandComplete(cmd)) = packet else {
                continue;
            };
            if cmd.command_opcode == 0x200A {
                cc_200a_seen += 1;
            }
            if cc_200a_seen >= 2 {
                phase.push(start_packet.clone());
                return true;
            }
        }
    }

    // Tertiary choice: force a delayed phase gap.
    if anchor_phase + 5 < input.phases().len() {
        input.phases_mut()[anchor_phase + 5].push(start_packet.clone());
        return true;
    }

    // Fallback: append to a later phase.
    if anchor_phase + 2 < input.phases().len() {
        input.phases_mut()[anchor_phase + 2].push(start_packet);
        return true;
    }
    if anchor_phase + 1 < input.phases().len() {
        input.phases_mut()[anchor_phase + 1].push(start_packet);
        return true;
    }

    false
}

fn patch_bt03_pb_adv_link_open_then_later_start_ext(input: &mut MetaInput) -> bool {
    // Build deterministic delayed-start layout first.
    let _ = patch_bt03_pb_adv_link_open_then_later_start(input);

    let mut start_packets: Vec<(usize, usize, AdvertisingReport)> = Vec::new();
    for (phase_idx, phase) in input.phases().iter().enumerate() {
        for (pkt_idx, packet) in phase.iter().enumerate() {
            let ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta)) = packet else {
                continue;
            };
            let LeMetaEventBody::AdvertisingReport(report_evt) = &le_meta.body else {
                continue;
            };
            if let Some(start_report) = report_evt.reports.iter().find(|r| is_pb_adv_start_candidate(r)).cloned() {
                start_packets.push((phase_idx, pkt_idx, start_report));
            }
        }
    }
    let Some((target_phase, target_pkt, _target_report)) = start_packets.last().cloned() else {
        return false;
    };

    for (phase_idx, pkt_idx, start_report) in start_packets {
        let packet = &mut input.phases_mut()[phase_idx][pkt_idx];
        let ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta)) = packet else {
            continue;
        };
        if phase_idx == target_phase && pkt_idx == target_pkt {
            let payload = legacy_adv_report_to_extended_payload(&start_report);
            let ext = LeExtendedAdvertisingReportEvent { num_reports: 0x1, payload };
            le_meta.parameter_total_length = 2 + ext.payload.len().min(usize::from(u8::MAX)) as u8;
            le_meta.body = LeMetaEventBody::ExtendedAdvertisingReport(ext);
        } else {
            let LeMetaEventBody::AdvertisingReport(report_evt) = &mut le_meta.body else {
                continue;
            };
            for report in &mut report_evt.reports {
                if is_pb_adv_start_candidate(report) {
                    report.event_type = 0x04;
                    report.data = vec![0x02, 0x01, 0x06];
                    report.data_length = report.data.len() as u8;
                }
            }
            le_meta.parameter_total_length = report_evt.parameter_total_length();
        }
    }
    true
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: rq4_input_patch <profile> <in.bin> <out.bin> <mutate_start>");
        process::exit(2);
    }

    let profile = &args[1];
    let in_path = &args[2];
    let out_path = &args[3];
    let mutate_start = args[4].parse::<usize>().unwrap_or(0);

    let mut input = MetaInput::from_file(in_path).expect("failed to load input");
    *input.mutate_start_mut() = mutate_start;

    let patched = match profile.as_str() {
        "bt03_pbadv_oversize" => patch_bt03_pb_adv_oversize(&mut input),
        "bt03_pbadv_link_open_then_start" => patch_bt03_pb_adv_link_open_then_start(&mut input),
        "bt03_pbadv_link_open_then_later_start" => patch_bt03_pb_adv_link_open_then_later_start(&mut input),
        "bt03_pbadv_link_open_then_later_start_ext" => patch_bt03_pb_adv_link_open_then_later_start_ext(&mut input),
        other => {
            eprintln!("unsupported profile: {other}");
            process::exit(2);
        }
    };

    if !patched {
        eprintln!("patch profile {profile} did not modify input");
        process::exit(1);
    }

    input.to_file(out_path).expect("failed to write output");
    println!("patched {profile}: {in_path} -> {out_path}");
}
