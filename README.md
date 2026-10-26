# HostFuzz

**HostFuzz** is a greybox fuzzing framework for BLE *Host* protocol stacks. It
fuzzes at the HCI boundary: a synthetic Controller answers the Host's HCI
commands, virtual peers drive GATT/L2CAP/SMP/Mesh interactions, and a
semantic-aware mutator focuses on values the Host actually interprets.

This repository is the artifact for the NDSS 2027 paper
“HostFuzz: A Framework for Scalable BLE Host Fuzzing via HCI Interaction”.
It contains the Rust framework, four execution backends (QEMU user-mode, ESP32
system-mode, Fuzzware, and native/AFL), 7 runnable demo targets, and the case
sets and runners for the RQ1 and RQ3 experiments.

## Repository layout

```text
.
├── apps/                       # backend front-ends
│   ├── usermode_fuzzer/
│   ├── esp32_fuzzer/
│   ├── fuzzware_fuzzer/
│   ├── src_fuzzer/
│   └── simulator/
├── crates/                     # framework libraries
├── demo/                       # 7 demo targets + shared assets
├── docs/                       # configuration, architecture
├── experiments/                # RQ1/RQ3 case sets and runners
├── scripts/                    # hostfuzz.py + Docker wrapper
├── Dockerfile
├── compose.yaml
├── Cargo.toml / Cargo.lock
└── README.md
```

## Running the demos

Build the default image, and optionally the full image that adds the Fuzzware
runtime:

```bash
docker build -t hostfuzz .
docker build --target full -t hostfuzz:full .
```

The helper wrapper runs the container with your UID/GID, so files in `outputs/`
are owned by you:

```bash
./scripts/hostfuzz-docker.sh list

./scripts/hostfuzz-docker.sh run \
  --case 01_btstack_sm_pairing_central --seconds 120

# Fuzzware demo
HOSTFUZZ_IMAGE=hostfuzz:full ./scripts/hostfuzz-docker.sh run \
  --case 06_nrf52_zephyr_gatt_write --seconds 120
```

| ID | Backend | Target | Image |
|---|---|---|---|
| `01_btstack_sm_pairing_central` | QEMU user | BTstack SM pairing central | default |
| `02_btstack_mesh_node` | QEMU user | BTstack Mesh node | default |
| `03_btstack_le_mitm` | QEMU user | BTstack LE MITM | default |
| `04_esp32_bluedroid_gatt_client` | QEMU system | BlueDroid GATT client | default |
| `05_esp32_nimble_gattc_gatts_coex` | QEMU system | NimBLE GATT client/server | default |
| `06_nrf52_zephyr_gatt_write` | Fuzzware | Zephyr nRF52 GATT write | `hostfuzz:full` |
| `07_zephyr_hr_central_native` | native/AFL | Zephyr BabbleSim HR central | default |

Every campaign seeds its own corpus; no initial seed input is required.
`--preset` selects the ablation mode (`full` by default; also `m1_m2`,
`m1_only`, `hci_random_floor`).

Each run is sandboxed under `outputs/<timestamp>_<case>/`:

```text
outputs/<timestamp>_<case>/
├── config.yaml                  # resolved configuration
├── run.log                      # fuzzer + target output
├── fuzz-<timestamp>/
│   ├── queue/                   # coverage-increasing MetaInput files
│   └── crashes/                 # objective/crash inputs
├── telemetry/
│   ├── coverage_over_time.csv   # edges, executions, corpus, objectives
│   └── run_telemetry.jsonl      # state and semantic-probe telemetry
└── summary.json                 # machine-readable run summary
```

Replay any corpus input and inspect the HCI traffic:

```bash
./scripts/hostfuzz-docker.sh replay --case 04_esp32_bluedroid_gatt_client \
  --input /outputs/<run>/fuzz-<timestamp>/queue/<input>
tcpdump -r outputs/<timestamp>_04_esp32_bluedroid_gatt_client_replay/replay.pcap
```

## Adding a new case

A case is a directory containing one YAML file and its target assets. Bundled
cases live under `demo/<id>/` and are selected with `--case <id>`; an arbitrary
location can be passed with `--config <path>`.

The backend is detected from the YAML:

| Backend | Detected by | Main executor keys |
|---|---|---|
| QEMU user-mode | default | `elf_path`, `cmd_args`, `env` |
| ESP32 system-mode | `flash_path` | `flash_path`, `efuse_path`, `pc_bios_path`, `hooks.*` |
| Fuzzware | `harness_config` | `harness_config`, `hook_module_dir`, `extra_python_paths`, `*_python` |
| native/AFL | `target_path` | `target_path`, `cmd_args`, `run_timeout_ms`, `allow_nonzero_exit` |

Minimal example for a BTstack-style UART target:

```yaml
fuzzer:
  work_dir: "./fuzz"

simulator:
  transport: "uart@/tmp/my_tty"
  protocol: "h4"
  timeout: 1000
  initial_timeout: 60000
  legacy_scan_reports:
    - event_type: 0
      address_type: Public
      address: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6]
      data: [0x02, 0x01, 0x06, 0x03, 0x03, 0x0D, 0x18]
      rssi: -40

executor:
  elf_path: "./my_host.elf"
  cmd_args: []
  env:
    BTSTACK_UART_DEVICE: "/tmp/my_tty"
```

Relative paths are resolved against the case directory. The runner rewrites
them to absolute paths and executes in a sandbox under `outputs/`, so it never
writes into the case directory.

Run the new case:

```bash
./scripts/hostfuzz-docker.sh run \
  --config /repo/demo/my_case/my_case.yaml --name my_case --seconds 300
```

The best starting point is the demo closest to your target:

- UART/TCP/UDP/VHCI Linux Host: `demo/01_btstack_sm_pairing_central/`
- ESP32 BlueDroid/NimBLE firmware: `demo/04_esp32_bluedroid_gatt_client/`
- Bare-metal Cortex-M firmware: `demo/06_nrf52_zephyr_gatt_write/`
- Native/AFL Host (Zephyr HCI-IPC): `demo/07_zephyr_hr_central_native/`

Checklist for a new case:

- [ ] Put the YAML and target assets under `demo/<id>/` (or any directory for `--config`).
- [ ] Choose the HCI transport and advertise the services/profiles the Host expects.
- [ ] Provide the assets required by the backend (ELF, flash/eFuse/ROM, memory map, or AFL-instrumented binary).
- [ ] Set `ablation.record_telemetry: true` if you want `run_telemetry.jsonl`.
- [ ] Run it once and inspect `run.log`, `summary.json`, and the corpus.

See [`docs/configuration.md`](docs/configuration.md) for the full YAML schema
and the existing `demo/` cases for complete examples.

## Reproducing RQ1 and RQ3

The experiment case sets live under `experiments/`:

| Experiment | Cases | Location |
|---|---|---|
| RQ1 — HostFuzz on the BLuEMan-derived cases | 10 | `experiments/RQ1-blueman/<case>/` |
| RQ3 — module ablation | 12 | `experiments/RQ3-ablation/<case>/` |

Both runners execute campaigns in Docker and generate a coverage figure:

```bash
# RQ1: HostFuzz only (BLuEMan is not executed)
python3 experiments/run_rq1.py --cases hr_central,central_otc --duration 600

# RQ3: selected cases and presets
python3 experiments/run_rq3.py \
  --cases 01_btstack,05_bluedroid,09_nrf \
  --presets m1_only,m1_m2,full --duration 600
```

Key options:

| Option | RQ1 (`run_rq1.py`) | RQ3 (`run_rq3.py`) |
|---|---|---|
| `--cases` | all 10 | all 12 |
| `--duration` | 86400 s | 43200 s |
| `--reps` | 1 | 1 |
| `--presets` | — | `m1_only,m1_m2,full` |
| `--jobs` | 4 | 4 |
| Output | `outputs/RQ1/<timestamp>/` | `outputs/RQ3/<timestamp>/` |

Results include the raw run directories, logs, telemetry, `summary.json`, a
manifest, and `fig7_hostfuzz_coverage.png` or `fig8_ablation_coverage.png`.
Use `--no-plot` to skip the figure.

For paper-scale runs use `--duration 86400` for RQ1 and
`--duration 43200 --reps 5` for RQ3. RQ3 cases 09-12 require `hostfuzz:full`;
the runner selects that image automatically. See
[`experiments/README.md`](experiments/README.md) for details.
