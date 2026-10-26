# Architecture

HostFuzz is a LibAFL-based fuzzer for BLE Host stacks. It treats the HCI
boundary as the fuzzing interface: packets emitted by the Host (H2C) are
observed and answered by a synthetic Controller, while C2H packets are
mutated and delivered back to the Host.

```
                  ┌──────────────────────────────────────────────┐
                  │                HostFuzz                       │
                  │                                              │
  corpus ────────►│  M3 Semantic-Aware Mutator                   │
                  │        │                                     │
                  │        ▼                                     │
                  │  M2 Adaptive Valid Packet Generator          │
                  │        │  virtual peers / controller events   │
                  │        ▼                                     │
                  │  M1 HCI Interaction Driver                   │
                  │        │  ordered C2H / H2C exchange          │
                  └────────┼─────────────────────────────────────┘
                           │ transport (UART/PTY/UDP/TCP/VHCI/IPC)
                  ┌────────▼─────────────────────────────────────┐
                  │  Target BLE Host (QEMU user/system, Fuzzware,│
                  │  native AFL-instrumented process)            │
                  └──────────────────────────────────────────────┘
```

## Execution model

`MetaInput` (`crates/ble/src/input.rs`) is a sequence of *interaction phases*.
Each phase is a `Vec<ControllerToHostPacket>`: the Controller packets that are
delivered in response to the Host packets observed during that phase.

1. The fuzzer selects an input from the corpus.
2. `MetaExecutorWrapper` (`crates/fuzzer/src/executor.rs`) starts the target
   and interacts with it through the `Simulator`.
3. M1 reads H2C packets, delimits phases, and injects the corresponding C2H
   packets from the input.
4. At the mutation point (`mutate_start`), M3 produces a mutated input; M2 may
   generate new C2H packets in response to newly observed Host behavior.
5. Coverage is collected from the backend (QEMU edge map, AFL shared memory,
   or Fuzzware), and the input is added to the corpus if it is interesting.
6. Crashes/timeouts are recorded as objectives.

The process is restarted for every execution, so emulator state and Host state
do not accumulate across iterations.

## M1 — HCI Interaction Driver

**Purpose.** Provide a deterministic, implementation-agnostic interface that
eliminates asynchronous Controller behavior.

**Key files**

- `crates/simulator/src/lib.rs` — simulator loop, phase handling, timeouts,
  packet capture (`pcap_dumper`), interaction scheduling.
- `crates/simulator/src/hci/` — H4/H5 framing and transports:
  - `posix_uart.rs` (`uart@/path`): creates a PTY and a symlink at the
    configured path; used by BTstack `posix-h4` targets.
  - `posix_udp.rs` (`udp-sync@bind-remote`): synchronous UDP exchange; used by
    ESP32 system-mode and Fuzzware targets.
  - `posix_tcp.rs` (`tcp@...`), `bluez_vhci.rs` (`vhci@...`), and
    `zephyr_ipc.rs` (`zephyr_ipc@sim=...,dev=...`) for the remaining Linux
    host targets and Zephyr's HCI-IPC emulator.
- `crates/simulator/src/hci/protocol/h4.rs`, `h5.rs` — packet framing.
- `crates/fuzzer/src/executor.rs` — `MetaExecutorWrapper` coordinates the
  target process, the simulator, coverage observers, and shared memory.
- `apps/*/src/executor.rs` — backend-specific target launch, exit detection,
  and sanitizers.

**Determinism.** M1 processes H2C packets in order and only injects C2H
packets at phase boundaries. It does not depend on Controller timing, which
removes the asynchronous packet-delivery nondeterminism discussed in the paper
(Figure 4).

**Initialization/control-plane probing.** During the dedicated bootstrap
phase, M1 mutates constraint-sensitive fields (e.g. HCI version/subversion,
vendor commands), observes whether the Host advances, and freezes the accepted
responses for the main campaign. The relevant flags are
`enable_vendor_bootstrap_search`, `enable_vendor_bootstrap_freeze`, and
`enable_vendor_response_marking` in `crates/simulator/src/ablation.rs`.

## M2 — Adaptive Valid Packet Generator

**Purpose.** Keep protocol progress without hand-written per-target state
machines. M2 observes Host behavior and synthesises the Controller events and
peer packets that the Host expects next.

**Key files**

- `crates/simulator/src/controller.rs` — HCI command dispatch.
- `crates/simulator/src/controller/`:
  - `advertising_manager.rs` — advertising sets, scan reports, periodic
    advertising, extended advertising.
  - `connection_manager.rs` — connection handles, connection complete events,
    disconnection.
  - `filter_accept_list.rs`, `iso.rs` — LE filter policies and ISO channels.
- `crates/simulator/src/entity/`:
  - `att.rs` — ATT server/client behavior, handle discovery, profile-guided
    probing.
  - `l2cap.rs` — signaling, credit-based flow control (CoC), connection
    management.
  - `smp.rs` — pairing/security state transitions.
  - `mesh.rs` — Mesh advertising bearer, PB-ADV, provisioning, proxy.
  - `ots.rs` — Object Transfer Service.
- `crates/simulator/src/entity.rs` — entity trait/dispatch.

**HCI command → event mapping.** M2 implements the mapping in the paper's
Table II (e.g. connectable advertising → `Command Complete` +
`LE Advertising Report` + `LE Connection Complete`; scanning → scan reports;
connection → handle lifecycle). Peer synthesis starts from HCI commands and
parameters rather than from a link-layer simulation; this is what removes the
per-controller and per-target adaptation.

**Probing.** For upper protocols, M2 probes in order: GAP advertisements →
L2CAP signaling → ATT discovery → GATT/ATT profile interactions → SMP. The
number of profile-guided probe steps is controlled by
`max_att_profile_guided_probe_steps` and the preset implemented by
`peer_gatt_profile_preset`.

## M3 — Semantic-Aware Packet Mutator

**Purpose.** Preserve protocol semantics while exploring the much smaller set
of values that a Host actually treats as meaningful (e.g. valid ATT handles,
connection IDs, lengths).

**Key files**

- `crates/fuzzer/src/mutator.rs` — mutation orchestration, semantic value
  management, the semantic/syntactic split.
- `crates/fuzzer/src/mutator/` — layer-specific mutators:
  `acl.rs`, `att.rs`, `event.rs`, `iso.rs`, `l2cap.rs`, `mesh.rs`, `sm.rs`.
- `crates/ble/src/{hci,l2cap,att,gatt,mesh}.rs` — packet structs and parsers
  used to locate mutable fields.
- `crates/simulator/src/telemetry.rs` — runtime semantic/profile telemetry
  (state flags, semantic probe counts, known handles, delivery ratio).
- `crates/fuzzer/src/campaign.rs` — coverage-over-time recorder.

**Semantic extraction.** M3 observes H2C packets, records values that the Host
accepts or references (handles, connection identifiers, MTU/credits, GATT
attributes, SMP keys), and maintains semantic sets per field. These sets are
updated during the campaign, not fixed from a specification.

**Mutation.** With probability `p`, a value is sampled from the observed
semantic set; otherwise a synthetic value is generated from the corresponding
field grammar (e.g. an unseen ATT handle). The mutated packet is re-encoded
with valid headers/lengths so that it survives lower-layer parsing and reaches
the target code path under test.

**Ablation.** `AblationMode` selects which of M1/M2/M3 are enabled; see
`crates/simulator/src/ablation.rs`. The demo runner exposes this as
`--preset`.

## Execution backends

| Backend | Target type | Coverage source | Entry point |
|---|---|---|---|
| `usermode_fuzzer` | Linux ELF, any QEMU user-mode arch | QEMU edge coverage (LibAFL QEMU) | `apps/usermode_fuzzer` |
| `esp32_fuzzer` | ESP32 firmware / flash image | QEMU system-mode edge coverage + heap sanitizer hooks | `apps/esp32_fuzzer` |
| `fuzzware_fuzzer` | Bare-metal Cortex-M firmware | Fuzzware MMIO modeling / harness | `apps/fuzzware_fuzzer` |
| `src_fuzzer` | Native AFL-instrumented process | AFL shared-memory edge map | `apps/src_fuzzer` |

All backends share the same M1/M2/M3 pipeline and the same `MetaInput` corpus
format, so an input can be replayed with `-r` to produce a pcap regardless of
which backend produced it.

## Telemetry and outputs

A campaign writes:

- `fuzz-<timestamp>/queue/` — coverage-increasing inputs (`MetaInput` encoded
  with postcard).
- `fuzz-<timestamp>/crashes/` — objective inputs and metadata.
- `telemetry/coverage_over_time.csv` — periodic coverage/execution/corpus
  samples (enabled by `simulator.ablation.record_telemetry`).
- `telemetry/run_telemetry.jsonl` — per-execution state flags and semantic
  metrics (M2/M3 observability; also used for ground-truth evaluation).
- `*.pcap` — HCI H4 traffic in run/replay mode.

These files are the basis for the paper's behavior coverage, packet
throughput, and ablation measurements.
