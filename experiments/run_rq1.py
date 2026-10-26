#!/usr/bin/env python3
"""Reproduce RQ1: run HostFuzz on the 10 BLuEMan-derived cases.

Only HostFuzz is executed (no external comparison tool). Each case runs in its
own Docker container; the script optionally renders a coverage-over-time figure
from the collected telemetry.

Examples:
    python3 experiments/run_rq1.py --cases hr_central,central_otc --duration 120
    python3 experiments/run_rq1.py --duration 86400 --reps 5 --jobs 5
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES_ROOT = ROOT / "experiments" / "RQ1-blueman"
DEFAULT_IMAGE = "hostfuzz"
CASES = [
    "central_otc",
    "gatt_write_central",
    "gatt_write_peripheral",
    "hr_central",
    "hr_peripheral",
    "le_credit_client",
    "le_credit_server",
    "peripheral_otc",
    "sm_pairing_central",
    "sm_pairing_peripheral",
]
TITLES = {
    "central_otc": "LE Central OTC",
    "gatt_write_central": "GATT Write Central",
    "gatt_write_peripheral": "GATT Write Peripheral",
    "hr_central": "Heart Rate Central",
    "hr_peripheral": "Heart Rate Peripheral",
    "le_credit_client": "LE Credit L2CAP Client",
    "le_credit_server": "LE Credit L2CAP Server",
    "peripheral_otc": "LE Peripheral OTC",
    "sm_pairing_central": "SM Pairing Central",
    "sm_pairing_peripheral": "SM Pairing Peripheral",
}
STATS_RE = re.compile(
    r"\[(?P<source>[^\]#]+)\s+#\d+\]\s+run time:\s+(?P<runtime>[^,]+),"
    r".*?edges:\s+(?P<edges>\d+)/"
)
RUNTIME_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([dhms])", re.I)


def find_config(case_dir: pathlib.Path) -> pathlib.Path:
    configs = sorted(case_dir.glob("*.yaml"))
    if not configs:
        raise SystemExit(f"no YAML config in {case_dir}")
    preferred = case_dir / f"{case_dir.name}.yaml"
    return preferred if preferred.is_file() else configs[0]


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


def image_exists(image: str) -> bool:
    return (
        subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def run_job(
    case: str,
    rep: int,
    duration: int,
    image: str,
    output_root: pathlib.Path,
) -> dict:
    case_dir = CASES_ROOT / case
    config = find_config(case_dir)
    rel_config = config.relative_to(ROOT)
    out = output_root / case / f"rep{rep:02d}"
    out.mkdir(parents=True, exist_ok=True)
    log_dir = output_root / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / f"{case}_rep{rep:02d}.log"
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
        image,
        "/repo/scripts/hostfuzz.py",
        "run",
        "--config",
        f"/repo/{rel_config}",
        "--name",
        case,
        "--seconds",
        str(duration),
        "--output",
        f"/outputs/{case}/rep{rep:02d}",
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
        f"[rq1] {case} rep{rep:02d} rc={rc} {elapsed:.1f}s status={status}",
        flush=True,
    )
    return {
        "case": case,
        "rep": rep,
        "seconds": duration,
        "returncode": rc,
        "status": status,
        "failure_time_s": failure_time,
        "elapsed_s": elapsed,
        "output": str(out),
    }


def parse_runtime(value: str) -> float:
    total = 0.0
    for number, unit in RUNTIME_RE.findall(value):
        total += float(number) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit.lower()]
    return total


def telemetry_paths(run_dir: pathlib.Path) -> list[pathlib.Path]:
    """Telemetry is written to ``rep/telemetry`` by hostfuzz.py.

    Older layouts put it under ``fuzz-*/telemetry``; accept both.
    """
    direct = run_dir / "telemetry" / "coverage_over_time.csv"
    if direct.is_file():
        return [direct]
    return sorted(run_dir.glob("fuzz-*/telemetry/coverage_over_time.csv"))


def telemetry_rows(run_dir: pathlib.Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in telemetry_paths(run_dir):
        with path.open(newline="", encoding="utf-8") as handle:
            rows.extend(csv.DictReader(handle))
    return rows


def run_status(run_dir: pathlib.Path) -> tuple[str, float | None]:
    """Return (status, failure_time_s).

    A seed failure means the fuzzer never obtained a corpus item: every seed
    attempt hit an objective and it aborted. Such a run has objectives but no
    meaningful coverage curve.
    """
    summary_path = run_dir / "summary.json"
    summary = {}
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            summary = {}
    rows = telemetry_rows(run_dir)
    seed_rows = [row for row in rows if row.get("sample_kind") == "seed_failure"]
    seed_failure = bool(seed_rows) or (
        summary.get("corpus_size", 0) == 0 and summary.get("objective_size", 0) > 0
    )
    failure_time = None
    if seed_rows:
        try:
            failure_time = max(float(row["elapsed_bucket_seconds"]) for row in seed_rows)
        except (KeyError, TypeError, ValueError):
            failure_time = None
    return ("seed_failure" if seed_failure else "ok"), failure_time


def run_timeline(run_dir: pathlib.Path) -> list[tuple[float, float]]:
    points: dict[float, float] = {}
    for row in telemetry_rows(run_dir):
        try:
            t = float(row["elapsed_bucket_seconds"])
            e = float(row["covered_edges"])
        except (KeyError, TypeError, ValueError):
            continue
        points[t] = max(points.get(t, 0.0), e)
    log_path = run_dir / "run.log"
    user: dict[float, float] = {}
    if log_path.is_file():
        with log_path.open(errors="replace") as handle:
            for line in handle:
                match = STATS_RE.search(line)
                if not match:
                    continue
                t = parse_runtime(match.group("runtime"))
                e = float(match.group("edges"))
                if match.group("source").strip() == "UserStats":
                    user[t] = max(user.get(t, 0.0), e)
    for t, e in user.items():
        points[t] = max(points.get(t, 0.0), e)
    return sorted(points.items())


def aggregate(files: list[list[tuple[float, float]]], grid):
    import numpy as np

    samples = []
    for points in files:
        if not points:
            continue
        times = np.array([p[0] for p in points], dtype=float)
        values = np.maximum.accumulate(np.array([p[1] for p in points], dtype=float))
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

    data = pathlib.Path(args.data)
    if not data.is_dir():
        raise SystemExit(f"data directory not found: {data}")
    series = {}
    max_time = 0.0
    for case in CASES:
        ok_runs = []
        failed_runs = []
        for path in sorted((data / case).glob("rep*")):
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
            series[case] = (ok_runs, failed_runs)
    if not series:
        raise SystemExit(f"no telemetry found under {data}")
    max_time = max(max_time, 1.0)
    grid = np.linspace(0, max_time, 300)
    fig, axes = plt.subplots(2, 5, figsize=(12.4, 4.8), sharey=False)
    axes = axes.flatten()
    rows = []
    for ax, case in zip(axes, CASES):
        if case not in series:
            ax.set_visible(False)
            continue
        ok_runs, failed_runs = series[case]
        if ok_runs:
            mean, lower, upper = aggregate(ok_runs, grid)
            ax.plot(grid / 3600.0, mean, color="#61CBF4", lw=1.1, label="HostFuzz")
            ax.fill_between(grid / 3600.0, lower, upper, color="#61CBF4", alpha=0.18, linewidth=0)
        for points, failure_time in failed_runs:
            if points:
                failure_time = failure_time if failure_time is not None else points[-1][0]
                ax.scatter([failure_time / 3600.0], [points[-1][1]], marker="x", s=36, color="#C00000", zorder=5)
        if failed_runs:
            ax.text(
                0.98,
                0.95,
                "seed failure" if not ok_runs else f"{len(failed_runs)} seed failure(s)",
                transform=ax.transAxes,
                ha="right",
                va="top",
                fontsize=6,
                color="#C00000",
            )
        ax.set_title(TITLES[case], fontsize=8)
        ax.grid(True, lw=0.3, alpha=0.5)
        ax.tick_params(labelsize=7)
        ax.set_xlabel("Time (h)", fontsize=7)
        ax.set_ylabel("Coverage (edges)", fontsize=7)
        status = "ok" if ok_runs else "seed_failure"
        rows.append(
            (
                case,
                len(ok_runs),
                f"{mean[-1]:.0f}" if ok_runs else "",
                f"{upper[-1]:.0f}" if ok_runs else "",
                status,
                f"{failed_runs[0][1]:.0f}" if failed_runs and failed_runs[0][1] is not None else "",
            )
        )
    fig.tight_layout()
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=200, bbox_inches="tight")
    print(f"[rq1] wrote {output}")
    if args.table:
        table = pathlib.Path(args.table)
        table.parent.mkdir(parents=True, exist_ok=True)
        with table.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["case", "successful_runs", "mean_final_edges", "max_final_edges", "status", "failure_time_s"])
            writer.writerows(rows)
        print(f"[rq1] wrote {table}")
    return 0


def plot_figure(data: pathlib.Path, image: str, output: pathlib.Path, table: pathlib.Path) -> int:
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
        "/repo/experiments/run_rq1.py",
        "--plot-only",
        "--data",
        "/data",
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
    parser.add_argument("--duration", type=int, default=86400, help="seconds per case (default: 86400)")
    parser.add_argument("--reps", type=int, default=1, help="repetitions per case")
    parser.add_argument("--jobs", type=int, default=4, help="parallel containers")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
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
    if not image_exists(args.image):
        raise SystemExit(
            f"image {args.image} not found; build it with: docker build -t {args.image} ."
        )
    if args.duration <= 0 or args.reps <= 0 or args.jobs <= 0:
        raise SystemExit("--duration, --reps and --jobs must be positive")
    cases = selected_cases(args.cases)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    output_root = pathlib.Path(args.output).resolve() if args.output else ROOT / "outputs" / "RQ1" / stamp
    output_root.mkdir(parents=True, exist_ok=True)
    print(
        f"[rq1] cases={len(cases)} reps={args.reps} duration={args.duration}s "
        f"jobs={args.jobs} output={output_root}"
    )
    jobs = [(case, rep) for case in cases for rep in range(1, args.reps + 1)]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = [
            executor.submit(run_job, case, rep, args.duration, args.image, output_root)
            for case, rep in jobs
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    write_manifest(output_root / "manifest.json", results)
    failed = [item for item in results if item["returncode"] != 0]
    if failed:
        print(f"[rq1] {len(failed)} jobs failed; see {output_root / 'logs'}", file=sys.stderr)
    seed_failures = [item for item in results if item.get("status") == "seed_failure"]
    for item in seed_failures:
        print(
            f"[rq1] WARNING {item['case']}/rep{item['rep']:02d}: seed failure "
            f"(no corpus, objectives only); see {item['output']}/run.log",
            file=sys.stderr,
        )
    if not args.no_plot and not failed:
        fig = output_root / "fig7_hostfuzz_coverage.png"
        table = output_root / "rq1_summary.csv"
        rc = plot_figure(output_root, args.image, fig, table)
        if rc != 0:
            print("[rq1] plotting failed", file=sys.stderr)
            return rc
    print(f"[rq1] done: {output_root}")
    return 1 if failed or seed_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
