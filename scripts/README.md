# Scripts

## `hostfuzz.py` — case runner

Primary entry point for the separate `demo/` suite and arbitrary case YAMLs.

```bash
python3 scripts/hostfuzz.py list
python3 scripts/hostfuzz.py run --case 01_btstack_sm_pairing_central --seconds 120
python3 scripts/hostfuzz.py run --config /path/to/case.yaml --name my_case --seconds 300
python3 scripts/hostfuzz.py replay --case 04_esp32_bluedroid_gatt_client \
  --input outputs/<run>/fuzz-<timestamp>/queue/<input>
python3 scripts/hostfuzz.py paper
```

Options:

| Command | Options |
|---|---|
| `run` | `--case` or `--config`, `--name`, `--instance`, `--seconds`, `--output`, `--preset`, `--log-level`, `--no-telemetry` |
| `replay` | `--case` or `--config`, `--name`, `--instance`, `--input` (required; a `MetaInput` corpus file), `--output`, `--log-level` |

Every run seeds its own corpus, so demo cases do not ship an initial `seed.bin`.
`replay` requires an explicit corpus file, typically a `queue/` input from a
completed run.

Environment:

- `HOSTFUZZ_BIN_DIR` — directory containing the backend binaries.
- `HOSTFUZZ_ROOT` — artifact root (default: parent of `scripts/`).
- `HOSTFUZZ_OUTPUT` — output root (default: `<root>/outputs`).
- `VIRTBLE_COVERAGE_INTERVAL_SECS` — telemetry sampling interval.

The runner sandboxes every execution:

- rewrites relative target paths to absolute paths;
- gives BTstack a unique PTY + `BTSTACK_UART_DEVICE`;
- gives Zephyr/BabbleSim `/tmp/bs_root/<sim>`, `USER=root`, and cleans stale
  FIFOs;
- copies ESP32 flash/eFuse/ROM assets to a writable sandbox;
- writes all outputs under `--output` (never into the case directory).

## `hostfuzz-docker.sh` — UID-safe wrapper

```bash
./scripts/hostfuzz-docker.sh list
./scripts/hostfuzz-docker.sh run --case 01_btstack_sm_pairing_central --seconds 120
HOSTFUZZ_IMAGE=hostfuzz:full ./scripts/hostfuzz-docker.sh \
  run --case 06_nrf52_zephyr_gatt_write --seconds 120
```

Mounts `outputs/` at `/outputs` and the repository at `/repo:ro`, and runs the
container as the invoking UID/GID so output files are user-owned.

## Paper experiments

The experiment reproduction scripts are `experiments/run_rq1.py` and
`experiments/run_rq3.py`; see `experiments/README.md`.
