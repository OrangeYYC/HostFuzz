#!/usr/bin/env python3
"""Reproduce RQ3: run the module-ablation matrix with HostFuzz.

Runs selected targets with one or more ablation presets in Docker and
optionally renders a coverage-over-time figure.

Examples:
    python3 experiments/run_rq3.py --cases 01_btstack --presets full --duration 600
    python3 experiments/run_rq3.py --duration 43200 --reps 5 --jobs 5
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from run_rq1 import aggregate, image_exists, run_status, run_timeline  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES_ROOT = ROOT / "experiments" / "RQ3-ablation"
DEFAULT_IMAGE = "hostfuzz"
DEFAULT_FULL_IMAGE = "hostfuzz:full"
CASES = [
    "01_btstack_sm_pairing_central",
    "02_btstack_le_credit_based_flow_control_mode_client",
    "03_btstack_gatt_heart_rate_client",
    "04_btstack_mesh_node",
    "05_bluedroid_gatt_client",
    "06_bluedroid_gatt_server",
    "07_nimble_ble_gattc_gatts_coex",
    "08_nimble_ble_l2cap_coc_blecent",
    "09_nrf_peripheral_gatt_write",
    "10_nrf_peripheral_hids",
    "11_nrf_peripheral_sc_only",
    "12_nrf_peripheral_nus",
]
PRESETS = ["m1_only", "m1_m2", "full"]
ALL_PRESETS = ["hci_random_floor", *PRESETS]
PRESET_STYLE = {
    "hci_random_floor": ("Random HCI floor (P0)", "#7F7F7F"),
    "m1_only": (r"$\mathrm{HostFuzz}_{\backslash\mathrm{M2},\backslash\mathrm{M3}}$", "#61CBF4"),
    "m1_m2": (r"$\mathrm{HostFuzz}_{\backslash\mathrm{M3}}$", "#E97132"),
    "full": (r"$\mathrm{HostFuzz}$", "#4EA72E"),
}
TITLES = {
    "01_btstack_sm_pairing_central": "BTstack SM Pairing Central",
    "02_btstack_le_credit_based_flow_control_mode_client": "BTstack LE Credit Client",
    "03_btstack_gatt_heart_rate_client": "BTstack GATT HR Client",
    "04_btstack_mesh_node": "BTstack Mesh Node",
    "05_bluedroid_gatt_client": "BlueDroid GATT Client",
    "06_bluedroid_gatt_server": "BlueDroid GATT Server",
    "07_nimble_ble_gattc_gatts_coex": "NimBLE GATT Coex",
    "08_nimble_ble_l2cap_coc_blecent": "NimBLE L2CAP CoC",
    "09_nrf_peripheral_gatt_write": "Zephyr nRF52 GATT Write",
    "10_nrf_peripheral_hids": "Zephyr nRF52 HIDS",
    "11_nrf_peripheral_sc_only": "Zephyr nRF52 SC Only",
    "12_nrf_peripheral_nus": "Zephyr nRF52 NUS",
}


def find_config(case_dir: pathlib.Path) -> pathlib.Path:
    preferred = case_dir / "fuzzware_fuzzer.yaml"
    if preferred.is_file():
        return preferred
    configs = sorted(case_dir.glob("*.yaml"))
    if not configs:
        raise SystemExit(f"no YAML config in {case_dir}")
    return configs[0]


def selected_cases(expr: str) -> list[str]:
    requested = [part.strip() for part in expr.split(",") if part.strip()]
    if not requested:
        return CASES
    chosen = [
        case
        for case in CASES
        if any(case == item or case.startswith(item) for item in requested)
    ]
    if not chosen:
        raise SystemExit(f"no case matched {expr!r}; available: {', '.join(CASES)}")
    return chosen


def selected_presets(expr: str) -> list[str]:
    requested = [part.strip() for part in expr.split(",") if part.strip()]
    if not requested:
        return PRESETS
    unknown = [item for item in requested if item not in ALL_PRESETS]
    if unknown:
        raise SystemExit(f"unknown preset(s): {unknown}; available: {ALL_PRESETS}")
    return requested


def image_for(config: pathlib.Path, image: str, full_image: str) -> str:
    text = config.read_text(encoding="utf-8", errors="replace")
    return full_image if "harness_config:" in text else image


def run_job(
    case: str,
    variant: str,
    rep: int,
    duration: int,
    image: str,
    full_image: str,
    output_root: pathlib.Path,
) -> dict:
    case_dir = CASES_ROOT / case
    config = find_config(case_dir)
    rel_config = config.relative_to(ROOT)
    out = output_root / case / variant / f"rep{rep:02d}"
    out.mkdir(parents=True, exist_ok=True)
    log_dir = output_root / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / f"{case}_{variant}_rep{rep:02d}.log"
    selected_image = image_for(config, image, full_image)
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-e",
        "HOME=/tmp",
        "-e",
        "USER=root",
        "-v",
        f"{ROOT}:/repo:ro",
        "-v",
        f"{output_root}:/outputs",
        "--entrypoint",
        "/usr/bin/python3",
        selected_image,
        "/repo/scripts/hostfuzz.py",
        "run",
        "--config",
        f"/repo/{rel_config}",
        "--name",
        case,
        "--preset",
        variant,
        "--seconds",
        str(duration),
        "--output",
        f"/outputs/{case}/{variant}/rep{rep:02d}",
        "--log-level",
        "error",
    ]
    started = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        rc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False).returncode
    elapsed = time.time() - started
    status, failure_time = run_status(out)
    print(
        f"[rq3] {case}/{variant} rep{rep:02d} rc={rc} {elapsed:.1f}s status={status}",
        flush=True,
    )
    return {
        "case": case,
        "variant": variant,
        "rep": rep,
        "seconds": duration,
        "returncode": rc,
        "status": status,
        "failure_time_s": failure_time,
        "elapsed_s": elapsed,
        "output": str(out),
    }


def aggregate_mean_range(files: list[list[tuple[float, float]]], grid):
    import numpy as np

    samples = []
    for points in files:
        if not points:
            continue
        times = np.array([point[0] for point in points], dtype=float)
        values = np.maximum.accumulate(
            np.array([point[1] for point in points], dtype=float)
        )
        samples.append(np.interp(grid, times, values, left=values[0], right=values[-1]))
    if not samples:
        zeros = np.zeros_like(grid)
        return zeros, zeros, zeros
    matrix = np.vstack(samples)
    return matrix.mean(axis=0), matrix.min(axis=0), matrix.max(axis=0)


def plot_only(args: argparse.Namespace) -> int:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams["mathtext.fontset"] = "custom"
    plt.rcParams["mathtext.rm"] = "Times New Roman"
    plt.rcParams["mathtext.it"] = "Times New Roman:italic"
    plt.rcParams["mathtext.bf"] = "Times New Roman:bold"

    data = pathlib.Path(args.data)
    if not data.is_dir():
        raise SystemExit(f"data directory not found: {data}")
    variants = selected_presets(args.presets)
    series: dict[tuple[str, str], tuple[list[list[tuple[float, float]]], list[tuple[list[tuple[float, float]], float | None]]]] = {}
    max_time = 0.0
    for case in CASES:
        for variant in variants:
            ok_runs = []
            failed_runs = []
            for path in sorted((data / case / variant).glob("rep*")):
                if not path.is_dir():
                    continue
                points = run_timeline(path)
                status, failure_time = run_status(path)
                if status == "seed_failure":
                    failed_runs.append((points, failure_time))
                elif points:
                    ok_runs.append(points)
                if points:
                    max_time = max(max_time, points[-1][0])
                if failure_time is not None:
                    max_time = max(max_time, failure_time)
            if ok_runs or failed_runs:
                series[(case, variant)] = (ok_runs, failed_runs)
    if not series:
        raise SystemExit(f"no telemetry found under {data}")
    max_time = max(max_time, 1.0)
    grid = np.linspace(0, max_time, 300)
    fig, axes = plt.subplots(2, 6, figsize=(13.2, 5.1), sharey=False)
    axes = axes.flatten()
    rows = []
    for ax, case in zip(axes, CASES):
        if not any((case, variant) in series for variant in variants):
            ax.set_visible(False)
            continue
        failed_variants = []
        for variant in variants:
            entry = series.get((case, variant))
            if not entry:
                continue
            ok_runs, failed_runs = entry
            label, color = PRESET_STYLE[variant]
            if ok_runs:
                mean, lower, upper = aggregate_mean_range(ok_runs, grid)
                ax.plot(grid / 3600.0, mean, color=color, lw=1.1, label=label)
                ax.fill_between(grid / 3600.0, lower, upper, color=color, alpha=0.15, linewidth=0)
            for points, failure_time in failed_runs:
                if points:
                    failure_time = failure_time if failure_time is not None else points[-1][0]
                    ax.scatter(
                        [failure_time / 3600.0],
                        [points[-1][1]],
                        marker="x",
                        s=36,
                        color=color,
                        zorder=5,
                    )
                failed_variants.append(label)
            rows.append(
                (
                    case,
                    variant,
                    len(ok_runs),
                    f"{mean[-1]:.0f}" if ok_runs else "",
                    "ok" if ok_runs else "seed_failure",
                    f"{failed_runs[0][1]:.0f}" if failed_runs and failed_runs[0][1] is not None else "",
                )
            )
        if failed_variants:
            ax.text(
                0.98,
                0.95,
                "seed failure: " + ", ".join(sorted(set(failed_variants))),
                transform=ax.transAxes,
                ha="right",
                va="top",
                fontsize=5,
                color="#C00000",
            )
        ax.set_title(TITLES[case], fontsize=8)
        ax.grid(True, lw=0.3, alpha=0.5)
        ax.tick_params(labelsize=7)
        ax.set_xlabel("Time (h)", fontsize=7)
        ax.set_ylabel("Coverage (edges)", fontsize=7)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=3, fontsize=9, frameon=False)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=200, bbox_inches="tight")
    print(f"[rq3] wrote {output}")
    if args.table:
        import csv

        table = pathlib.Path(args.table)
        table.parent.mkdir(parents=True, exist_ok=True)
        with table.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["case", "variant", "successful_runs", "mean_final_edges", "status", "failure_time_s"])
            writer.writerows(rows)
        print(f"[rq3] wrote {table}")
    return 0


def plot_figure(
    data: pathlib.Path,
    image: str,
    presets: list[str],
    output: pathlib.Path,
    table: pathlib.Path,
) -> int:
    command = [
        "docker",
        "run",
        "--rm",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-e",
        "HOME=/tmp",
        "-v",
        f"{data}:/data",
        "-v",
        f"{ROOT}:/repo:ro",
        "--entrypoint",
        "/usr/bin/python3",
        image,
        "/repo/experiments/run_rq3.py",
        "--plot-only",
        "--data",
        "/data",
        "--presets",
        ",".join(presets),
        "--output",
        f"/data/{output.name}",
        "--table",
        f"/data/{table.name}",
    ]
    return subprocess.run(command, check=False).returncode


def write_manifest(path: pathlib.Path, results: list[dict]) -> None:
    """Merge results into an existing manifest, replacing matching jobs."""
    merged: dict[tuple, dict] = {}
    if path.is_file():
        try:
            for item in json.loads(path.read_text()):
                merged[(item.get("case"), item.get("variant"), item.get("rep"))] = item
        except (json.JSONDecodeError, TypeError):
            merged = {}
    for item in results:
        merged[(item.get("case"), item.get("variant"), item.get("rep"))] = item
    path.write_text(json.dumps(list(merged.values()), indent=2) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default="", help="comma-separated case names or prefixes")
    parser.add_argument("--presets", default=",".join(PRESETS), help="comma-separated ablation presets")
    parser.add_argument("--duration", type=int, default=43200, help="seconds per case (default: 43200)")
    parser.add_argument("--reps", type=int, default=1, help="repetitions per case/variant")
    parser.add_argument("--jobs", type=int, default=4, help="parallel containers")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--full-image", default=DEFAULT_FULL_IMAGE)
    parser.add_argument("--output", default="", help="output root")
    parser.add_argument("--no-plot", action="store_true", help="skip figure generation")
    parser.add_argument("--plot-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--data", default="", help=argparse.SUPPRESS)
    parser.add_argument("--table", default="", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.plot_only:
        return plot_only(args)
    if args.duration <= 0 or args.reps <= 0 or args.jobs <= 0:
        raise SystemExit("--duration, --reps and --jobs must be positive")
    cases = selected_cases(args.cases)
    presets = selected_presets(args.presets)
    if not image_exists(args.image):
        raise SystemExit(
            f"image {args.image} not found; build it with: docker build -t {args.image} ."
        )
    needs_full = any(
        image_for(find_config(CASES_ROOT / case), args.image, args.full_image) == args.full_image
        for case in cases
    )
    if needs_full and not image_exists(args.full_image):
        raise SystemExit(
            f"image {args.full_image} not found; build it with: "
            f"docker build --target full -t {args.full_image} ."
        )
    stamp = time.strftime("%Y%m%d-%H%M%S")
    output_root = pathlib.Path(args.output).resolve() if args.output else ROOT / "outputs" / "RQ3" / stamp
    output_root.mkdir(parents=True, exist_ok=True)
    print(
        f"[rq3] cases={len(cases)} presets={presets} reps={args.reps} "
        f"duration={args.duration}s jobs={args.jobs} output={output_root}"
    )
    jobs = [
        (case, variant, rep)
        for case in cases
        for variant in presets
        for rep in range(1, args.reps + 1)
    ]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = [
            executor.submit(
                run_job,
                case,
                variant,
                rep,
                args.duration,
                args.image,
                args.full_image,
                output_root,
            )
            for case, variant, rep in jobs
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    write_manifest(output_root / "manifest.json", results)
    failed = [item for item in results if item["returncode"] != 0]
    if failed:
        print(f"[rq3] {len(failed)} jobs failed; see {output_root / 'logs'}", file=sys.stderr)
    seed_failures = [item for item in results if item.get("status") == "seed_failure"]
    for item in seed_failures:
        print(
            f"[rq3] WARNING {item['case']}/{item['variant']}/rep{item['rep']:02d}: "
            f"seed failure (no corpus, objectives only); see {item['output']}/run.log",
            file=sys.stderr,
        )
    if not args.no_plot and not failed:
        figure_image = args.full_image if needs_full else args.image
        rc = plot_figure(
            output_root,
            figure_image,
            presets,
            output_root / "fig8_ablation_coverage.png",
            output_root / "rq3_summary.csv",
        )
        if rc != 0:
            print("[rq3] plotting failed", file=sys.stderr)
            return rc
    print(f"[rq3] done: {output_root}")
    return 1 if failed or seed_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
