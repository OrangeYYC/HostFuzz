# Configuration reference

A HostFuzz case is a YAML file consumed by a backend binary:

```bash
<backend-fuzzer> -f -l <level> case.yaml          # fuzz
<backend-fuzzer> -r -l <level> case.yaml in out.pcap  # replay one MetaInput
```

The file has three top-level sections: `fuzzer`, `simulator`, and `executor`.
Relative paths are resolved against the directory containing the YAML file
(`resolve_path` in `crates/fuzzer/src/app.rs`).

`scripts/hostfuzz.py` prepares a sandbox under the output directory before
launching a case:

- all relative target paths are rewritten to absolute paths;
- BTstack UART paths are replaced with a unique `/tmp/hostfuzz_*` PTY and
  `executor.env.BTSTACK_UART_DEVICE`;
- Zephyr HCI-IPC runs get `/tmp/bs_root/<sim>`, stale FIFOs are removed, and
  `USER=root` is set for the target;
- ESP32 flash/eFuse/ROM assets are copied into the sandbox because QEMU expects
  writable files.

This lets the repository be mounted read-only. For an arbitrary case, use
`hostfuzz run --config <path>`; for demo cases, `--case <name>`.

## `fuzzer`

| Key | Type | Description |
|---|---|---|
| `work_dir` | string | Prefix for campaign directories. The fuzzer creates `<work_dir>-<timestamp>/queue` and `<work_dir>-<timestamp>/crashes`. It never reuses an existing directory. |

Environment overrides:

- `VIRTBLE_FUZZ_WORK_DIR` or `FUZZ_WORK_ROOT` — replace `work_dir`.
- `VIRTBLE_INITIAL_INPUT`, `INITIAL_INPUT`, `FUZZ_INITIAL_INPUT` — path to a
  `MetaInput` file used instead of the blank seed.
- `VIRTBLE_CFG_BASE_DIR` — override the base directory for relative paths.
- `VIRTBLE_COVERAGE_INTERVAL_SECS` — telemetry sampling interval (default 5).
- `VIRTBLE_FUZZ_SEED` — deterministic RNG seed (default 12345).

## `simulator`

| Key | Default | Description |
|---|---|---|
| `transport` | required | HCI transport string; see below. |
| `protocol` | required | HCI framing: `h4` (UART) or `h5` (three-wire). |
| `timeout` | required | Per-round read timeout in milliseconds. |
| `initial_timeout` | required | Timeout for the first Host packet (bring-up may be slow). |
| `public_device_address` | `00:00:00:00:00:00` | Controller public address. |
| `initial_local_version_information` | unset | Override `HCI_Read_Local_Version_Information` response. |
| `keep_alive_on_timeout_until_child_exit` | `false` | Keep the target alive after a round timeout (used by Fuzzware). |
| `replay_fuzz_phases` | `true` | Replay input phases before the mutation point. |
| `freeze_version_mutation` | `false` | Disable HCI version/subversion mutation after bootstrap. |
| `freeze_vendor_response_mutation` | `false` | Disable vendor-response mutation after bootstrap. |
| `round_timeout` | `0` | Optional extra wait between interaction rounds. |
| `max_acl_packets_per_round` | `0` | Cap ACL packets per round (0 = unlimited). |
| `max_hci_packets_per_round` | `0` | Cap all HCI packets per round (0 = unlimited). |
| `legacy_scan_reports` | default report | Synthetic `LE Advertising Report` entries (event type, address type, address, data, RSSI). |
| `emit_default_legacy_scan_report` | `true` | Emit the default report when no list is configured. |
| `emit_extended_adv_probe_on_le_event_mask` | `false` | Probe extended advertising after `LE Set Event Mask`. |
| `targeted_bootstrap_vendor_opcodes` | `[]` | Vendor opcodes to probe during bootstrap. |
| `max_att_profile_guided_probe_steps` | `6` | ATT/GATT profile-guided probe budget. |
| `att_semantic_probe_order` | default | Ordering strategy for ATT semantic probes. |
| `le_credit` | `{}` | LE credit-based flow-control parameters (PSM, MTU, MPS, credits, auto-open/stream). |
| `supported_states` | `[]` | Per-slot state hints for matching `ATTC_DEMO`-style host logic. |
| `peer_gatt_profile_preset` | `{}` | GATT profile preset used by M2's virtual peer. |
| `ablation` | see below | Module ablation and telemetry. |

### `simulator.ablation`

| Key | Values | Description |
|---|---|---|
| `mode` | `full`, `m1_m2`, `m1_only`, `hci_random_floor` | Module ablation (paper RQ3). |
| `record_telemetry` | bool | Write `coverage_over_time.csv` and `run_telemetry.jsonl`. |
| `telemetry_dir` | path | Output directory (default `./ablation-results/<case>`). |
| `case_name` | string | Label written into telemetry (default: YAML file stem). |

### Transports

| Prefix | Format | Use |
|---|---|---|
| `uart@` | `uart@/tmp/ttyACM0` | Creates a PTY and symlinks it at the given path. BTstack `posix-h4` targets open the same path; set `BTSTACK_UART_DEVICE` in `executor.env` to match. |
| `udp-sync@` | `udp-sync@<host_ip:port>-<controller_ip:port>` | Synchronous UDP; `<host>` is the target's address, `<controller>` is the address HostFuzz binds. Sends a `0xff` phase-end marker. Used by ESP32 and Fuzzware. |
| `udp-async@` | same as above | Asynchronous UDP (no phase-end marker). |
| `tcp-sync@` / `tcp-async@` | `tcp-sync@<bind_addr>` (e.g. `tcp-sync@127.0.0.1:9000`) | HostFuzz listens; the target connects. `tcp-sync` sends a phase-end marker. |
| `vhci` | `vhci` | BlueZ `/dev/vhci` (Linux host target). |
| `zephyr_ipc@` | `zephyr_ipc@sim=trial_sim,dev=0,phy=HCIIPC,mode=hci_ipc` | Zephyr/BabbleSim HCI-IPC FIFOs under `/tmp/bs_root/<sim>`. |

## `executor` — QEMU user-mode (`usermode_fuzzer`)

| Key | Description |
|---|---|
| `elf_path` | Target ELF. |
| `cmd_args` | Arguments passed to the guest program. |
| `env` | Extra environment variables; `BTSTACK_*`, `BSIM_*` and `QEMU_SET_ENV` are forwarded. |
| `chroot_path` | Optional chroot for firmware root filesystems. |
| `allocate_stdio_pty` | Attach the guest's stdio to a PTY (some targets require a tty). |

Coverage is restricted to executable mappings of the target ELF; set
`VIRTBLE_DISABLE_TARGET_COVERAGE_FILTER=1` to disable this filter.

## `executor` — QEMU system-mode ESP32 (`esp32_fuzzer`)

| Key | Description |
|---|---|
| `flash_path` | Flash image (`qemu_flash.bin`). |
| `efuse_path` | eFuse image. |
| `pc_bios_path` | Directory containing `esp32-v3-rom.bin` and `esp32-v3-rom-app.bin`. |
| `hooks.controller.*` | Guest addresses of ESP-IDF controller/VHCI functions. |
| `hooks.sanitizer.*` | Guest addresses of malloc/free/panic functions and heap/code area descriptors. |

The hooks are per-firmware; they are recorded in each ESP32 case YAML. The
sanitizer converts heap overflows and panic-handler entries into observable
objectives.

## `executor` — Fuzzware (`fuzzware_fuzzer`)

| Key | Description |
|---|---|
| `harness_python` / `modeling_python` | Python interpreters for the harness and modeling environments. |
| `harness_module` | Default `fuzzware_harness.harness`. |
| `harness_root` | Fuzzware checkout (e.g. `/opt/fuzzware/emulator/harness`). |
| `harness_config` | Fuzzware memory-map/handler YAML. |
| `hook_module_dir` | Directory containing Python hook modules referenced by the config. |
| `extra_python_paths` | Additional `sys.path` entries (Unicorn bindings, modeling). |
| `work_dir` | Working directory for the harness. |
| `harness_args` | Extra harness arguments. |
| `env` | Environment variables for the harness. |
| `udp_bind` / `udp_remote` | Override UDP endpoints. |
| `udp_timeout_ms` | UDP read timeout (default 80 ms). |
| `run_timeout_ms` | Per-execution timeout (default 1000 ms). |
| `allow_nonzero_exit` | Treat non-zero exit as normal termination. |
| `auto_modeling` | Enable Fuzzware's automatic MMIO modeling. |
| `model_timeout_sec` / `model_max_states` | Modeling budget. |

## `executor` — native/source (`src_fuzzer`)

| Key | Description |
|---|---|
| `target_path` | AFL-instrumented executable. |
| `cmd_args` | Target arguments. |
| `work_dir` | Working directory. |
| `env` | Extra environment variables. |
| `allow_nonzero_exit` | Treat non-zero exit as normal completion. |
| `auto_append_sim_args` | Append BabbleSim `-s=<sim>` / `-d=<dev>` arguments (default true). |
| `sim_id` / `device_id` | Values used by the appended arguments. |
| `run_timeout_ms` | Per-execution timeout. |

The executor exports `__AFL_SHM_ID` and `AFL_MAP_SIZE` for the target, so the
target must be built with AFL instrumentation (or an equivalent
`__afl_area_ptr` implementation).

## MetaInput files

The corpus files produced under `queue/` are postcard-encoded `MetaInput`
values. They contain the interaction phases, the mutation start index, local
version information, vendor-response marks, and (for Fuzzware) the MMIO byte
seed. They are stable across builds of the same code and can be replayed with
`-r`.

To inspect one without writing Rust code, replay it and inspect the resulting
HCI pcap:

```bash
<backend-fuzzer> -r -l debug case.yaml path/to/queue/0-<id> replay.pcap
tcpdump -r replay.pcap
```

The development tree also contains `apps/usermode_fuzzer/src/bin/rq4_input_dump.rs`,
a small helper that decodes `MetaInput` fields.
