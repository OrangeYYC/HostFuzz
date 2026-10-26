# Experiments

This directory contains only the paper experiment material: target binaries,
case configurations, and **two reproduction scripts**.

```
experiments/
├── run_rq1.py               # RQ1: run HostFuzz on the 10 comparison cases
├── run_rq3.py               # RQ3: run the 12-case ablation matrix
├── RQ1-blueman/             # 10 cases (target.exe + YAML)
└── RQ3-ablation/            # 12 cases (binary + YAML + presets + common assets)
```

The scripts run every campaign in Docker. Build the images first:

```bash
docker build -t hostfuzz .
docker build --target full -t hostfuzz:full .   # needed by RQ3 cases 09-12
```

## RQ1 — HostFuzz on the 10 comparison cases

Runs only our tool; the BLuEMan comparison tool is not executed.

```bash
# all 10 cases, 2 minutes each
python3 experiments/run_rq1.py --duration 120

# selected cases, 3 repetitions, 4 parallel containers
python3 experiments/run_rq1.py \
  --cases hr_central,central_otc,gatt_write_central \
  --duration 600 --reps 3 --jobs 4
```

| Option | Default | Meaning |
|---|---|---|
| `--cases` | all 10 | Comma-separated names or prefixes. |
| `--duration` | `86400` | Fuzzing seconds per case. |
| `--reps` | `1` | Repetitions per case. |
| `--jobs` | `4` | Parallel Docker containers. |
| `--image` | `hostfuzz` | Docker image. |
| `--output` | `outputs/RQ1/<timestamp>` | Output directory. |
| `--no-plot` | off | Skip figure generation. |

Output: `outputs/RQ1/<timestamp>/<case>/repNN/` (run logs, telemetry,
`summary.json`) plus `fig7_hostfuzz_coverage.png` and `rq1_summary.csv`.

## RQ3 — module ablation on the 12 cases

Runs the selected ablation presets for every selected case.

```bash
# all cases, all three presets, 2 minutes each
python3 experiments/run_rq3.py --duration 120

# selected cases and one preset, 10 minutes each
python3 experiments/run_rq3.py \
  --cases 01_btstack,05_bluedroid,09_nrf \
  --presets full --duration 600 --jobs 3
```

| Option | Default | Meaning |
|---|---|---|
| `--cases` | all 12 | Comma-separated names or prefixes. |
| `--presets` | `m1_only,m1_m2,full` | Ablation variants. `hci_random_floor` is also accepted. |
| `--duration` | `43200` | Fuzzing seconds per case/variant. |
| `--reps` | `1` | Repetitions per case/variant. |
| `--jobs` | `4` | Parallel Docker containers. |
| `--image` | `hostfuzz` | Image for QEMU/native cases. |
| `--full-image` | `hostfuzz:full` | Image for Fuzzware cases (09-12). |
| `--output` | `outputs/RQ3/<timestamp>` | Output directory. |
| `--no-plot` | off | Skip figure generation. |

Output: `outputs/RQ3/<timestamp>/<case>/<preset>/repNN/` plus
`fig8_ablation_coverage.png` and `rq3_summary.csv`.

## Notes

- Paper settings: RQ1 uses 24 h per case; RQ3 uses 12 h per case/variant with
  five repetitions. Use `--duration 86400` / `--duration 43200 --reps 5`.
- Each job gets its own container, so UART PTYs, UDP ports, and
  `/tmp/bs_root` do not collide.
- The scripts use `/usr/bin/python3` inside the images for plotting; the
  Fuzzware venv on `PATH` does not include matplotlib.