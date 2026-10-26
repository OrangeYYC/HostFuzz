#!/usr/bin/env python3
"""HostFuzz demo runner.

This script is intentionally self-contained: it prepares a per-run sandbox,
rewrites the case configuration to absolute paths, launches the right backend
binary, and summarises corpus/crash/telemetry/pcap outputs.

Requires PyYAML (``apt install python3-yaml`` or ``pip install pyyaml``).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get("HOSTFUZZ_ROOT", Path(__file__).resolve().parents[1])).resolve()
CASES_DIR = ROOT / "demo"
DEFAULT_OUTPUT = Path(os.environ.get("HOSTFUZZ_OUTPUT", ROOT / "outputs"))

APP_FOR_BACKEND = {
    "usermode": ("usermode_fuzzer", "usermode_fuzzer"),
    "esp32": ("esp32_fuzzer", "esp32_fuzzer"),
    "fuzzware": ("fuzzware_fuzzer", "fuzzware_fuzzer"),
    "src": ("src_fuzzer", "src_fuzzer"),
}

STATE_FLAGS = [
    "entered_scanning",
    "entered_advertising",
    "entered_connection",
    "peer_created",
    "entered_pairing",
    "discovery_started",
    "discovery_completed",
    "semantic_interaction_started",
]


# --------------------------------------------------------------------------- #
# YAML helpers
# --------------------------------------------------------------------------- #
def _yaml() -> Any:
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on host
        raise SystemExit(
            "PyYAML is required. Install it with 'pip install pyyaml' "
            "or run inside the HostFuzz Docker image."
        ) from exc
    return yaml


def load_config(path: Path) -> dict[str, Any]:
    return _yaml().safe_load(path.read_text(encoding="utf-8"))


def dump_config(config: dict[str, Any], path: Path) -> None:
    path.write_text(
        _yaml().safe_dump(config, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# Case discovery and binary resolution
# --------------------------------------------------------------------------- #
def case_config(case_dir: Path) -> Path | None:
    configs = sorted(p for p in case_dir.glob("*.yaml"))
    return configs[0] if configs else None


def detect_backend(config_path: Path) -> str:
    text = config_path.read_text(encoding="utf-8")
    if re.search(r"^\s*harness_config\s*:", text, re.M):
        return "fuzzware"
    if re.search(r"^\s*flash_path\s*:", text, re.M):
        return "esp32"
    if re.search(r"^\s*target_path\s*:", text, re.M):
        return "src"
    return "usermode"


def discover_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for directory in sorted(CASES_DIR.iterdir()):
        if not directory.is_dir() or directory.name == "common":
            continue
        config = case_config(directory)
        if config is None:
            continue
        cases.append(
            {
                "case": directory.name,
                "dir": directory,
                "config": config,
                "backend": detect_backend(config),
            }
        )
    return cases


def get_case(name: str) -> dict[str, Any]:
    for case in discover_cases():
        if case["case"] == name or case["case"].startswith(name):
            return case
    available = ", ".join(c["case"] for c in discover_cases())
    raise SystemExit(f"unknown case '{name}'. Available: {available}")


def case_from_config(config_path: str, name: str | None = None) -> dict[str, Any]:
    """Build a case descriptor for an arbitrary case YAML.

    This is the entry point for paper cases and user-provided targets that are
    not part of the bundled demo suite.
    """
    path = Path(config_path).resolve()
    if not path.is_file():
        raise SystemExit(f"config not found: {path}")
    case_name = name.strip() if name else path.stem
    return {
        "case": case_name,
        "dir": path.parent,
        "config": path,
        "backend": detect_backend(path),
    }


def select_case(args: argparse.Namespace) -> dict[str, Any]:
    config = getattr(args, "config", "")
    if config:
        return case_from_config(config, getattr(args, "name", ""))
    return get_case(args.case)


def resolve_binary(backend: str) -> Path:
    app, binary = APP_FOR_BACKEND[backend]
    override = os.environ.get("HOSTFUZZ_BIN_DIR")
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override) / binary)
    candidates.extend(
        [
            ROOT / "apps" / app / "target-x86_64" / "release" / binary,
            ROOT / "apps" / app / "target" / "release" / binary,
        ]
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which(binary)
    if found:
        return Path(found)
    raise SystemExit(
        f"cannot find '{binary}' for backend '{backend}'. Build it first "
        f"(see README) or set HOSTFUZZ_BIN_DIR to the directory containing "
        f"the fuzzer binaries."
    )


# --------------------------------------------------------------------------- #
# Sandbox preparation
# --------------------------------------------------------------------------- #
def _absolute_from_case(case_dir: Path, value: str | None) -> str | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = (case_dir / path).resolve()
    return str(path)


def prepare_run(
    case: dict[str, Any],
    out_dir: Path,
    preset: str,
    keep_telemetry: bool,
    instance: str = "",
) -> tuple[Path, dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    case_dir: Path = case["dir"]
    config = load_config(case["config"])
    simulator = config.setdefault("simulator", {})
    executor = config.setdefault("executor", {})
    fuzzer = config.setdefault("fuzzer", {})

    fuzzer["work_dir"] = str(out_dir / "fuzz")

    suffix = f"_{re.sub(r'[^A-Za-z0-9_.-]', '_', instance)}" if instance else ""
    unique = f"hostfuzz_{case['case']}_{os.getpid()}{suffix}"
    transport = simulator.get("transport", "")
    if isinstance(transport, str) and transport.startswith("uart@"):
        simulator["transport"] = f"uart@/tmp/{unique}.tty"
        executor.setdefault("env", {})["BTSTACK_UART_DEVICE"] = f"/tmp/{unique}.tty"

    # Zephyr/BabbleSim targets derive their FIFO root from $USER (/tmp/bs_<user>)
    # and expect /tmp/bs_root, so force USER=root and pre-create the directory.
    if isinstance(transport, str) and (transport.startswith("zephyr_ipc@") or transport.startswith("zephyr-ipc@")):
        sim_id = "trial_sim"
        for token in transport.split("@", 1)[-1].split(","):
            if token.startswith(("sim=", "sim_id=", "s=")):
                sim_id = token.split("=", 1)[1]
                break
        else:
            if "-" in transport.split("@", 1)[-1]:
                sim_id = transport.split("@", 1)[-1].rsplit("-", 1)[0]
        if instance:
            new_sim = f"{sim_id}_{re.sub(r'[^A-Za-z0-9_.-]', '_', instance)}"
            simulator["transport"] = transport.replace(f"sim={sim_id}", f"sim={new_sim}").replace(
                f"sim_id={sim_id}", f"sim_id={new_sim}"
            )
            cmd_args = executor.get("cmd_args", [])
            executor["cmd_args"] = [
                f"-s={new_sim}" if str(arg).startswith("-s=") else arg for arg in cmd_args
            ]
            sim_id = new_sim
        sim_dir = Path("/tmp/bs_root") / sim_id
        sim_dir.mkdir(parents=True, exist_ok=True)
        for stale in list(sim_dir.glob("*.dtp")) + list(sim_dir.glob("*.ptd")) + list(sim_dir.glob("*.lock")):
            stale.unlink(missing_ok=True)
        executor.setdefault("env", {})["USER"] = "root"
        executor["env"].setdefault("LOGNAME", "root")

    ablation = simulator.setdefault("ablation", {})
    ablation["mode"] = preset
    ablation["record_telemetry"] = bool(keep_telemetry)
    ablation["telemetry_dir"] = str(out_dir / "telemetry")

    for key in ("elf_path", "flash_path", "efuse_path", "pc_bios_path", "target_path"):
        if key in executor:
            executor[key] = _absolute_from_case(case_dir, str(executor[key]))

    # QEMU's ESP32 eFuse/flash drives expect writable files. Copy the small
    # firmware assets into the sandbox so runs never touch the case directory
    # and work with read-only source mounts.
    if "flash_path" in executor:
        assets = out_dir / "assets"
        assets.mkdir(parents=True, exist_ok=True)
        for key, target_name in (("flash_path", "flash.bin"), ("efuse_path", "efuse.bin")):
            source = Path(str(executor[key]))
            if source.is_file():
                shutil.copy2(source, assets / target_name)
                executor[key] = str(assets / target_name)
        bios = Path(str(executor.get("pc_bios_path", "")))
        if bios.is_dir():
            rom_dir = assets / "roms"
            rom_dir.mkdir(exist_ok=True)
            for entry in bios.iterdir():
                if entry.is_file():
                    shutil.copy2(entry, rom_dir / entry.name)
            executor["pc_bios_path"] = str(rom_dir)
    if "harness_config" in executor:
        executor["harness_config"] = _absolute_from_case(case_dir, str(executor["harness_config"]))
        executor["hook_module_dir"] = _absolute_from_case(case_dir, str(executor.get("hook_module_dir", ".")))
    if "extra_python_paths" in executor:
        executor["extra_python_paths"] = [
            _absolute_from_case(case_dir, str(path)) for path in executor["extra_python_paths"]
        ]

    config_path = out_dir / "config.yaml"
    dump_config(config, config_path)

    # Fuzzware memory-map files are resolved relative to the harness config.
    if case["backend"] == "fuzzware":
        source_harness = Path(str(executor.get("harness_config", "./fuzzware.yml")))
        if not source_harness.is_absolute():
            source_harness = (case_dir / source_harness).resolve()
        harness_config = out_dir / source_harness.name
        text = source_harness.read_text(encoding="utf-8")
        text = re.sub(
            r"(^\s*file\s*:\s*)(\./\S+)",
            lambda match: match.group(1) + _absolute_from_case(case_dir, match.group(2)),
            text,
            flags=re.M,
        )
        harness_config.write_text(text, encoding="utf-8")
        config = load_config(config_path)
        config["executor"]["harness_config"] = str(harness_config)
        dump_config(config, config_path)

    return config_path, config


def run_binary(
    binary: Path,
    args: list[str],
    cwd: Path,
    log_path: Path,
    seconds: int | None,
) -> int:
    command = [str(binary), *args]
    if seconds is not None:
        command = [
            "timeout",
            "--signal=SIGINT",
            "--kill-after=15",
            str(seconds),
            *command,
        ]
    env = os.environ.copy()
    env.setdefault("VIRTBLE_COVERAGE_INTERVAL_SECS", "2")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        proc = subprocess.run(command, cwd=str(cwd), stdout=log, stderr=subprocess.STDOUT, env=env)
    return int(proc.returncode or 0)


# --------------------------------------------------------------------------- #
# Result parsing
# --------------------------------------------------------------------------- #
def read_coverage(out_dir: Path) -> dict[str, Any]:
    csv_path = out_dir / "telemetry" / "coverage_over_time.csv"
    if not csv_path.is_file():
        return {}
    max_edges = 0
    last: dict[str, str] = {}
    last_executions = 0
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            last = row
            try:
                max_edges = max(max_edges, int(row.get("covered_edges", 0)))
            except (TypeError, ValueError):
                pass
            try:
                last_executions = max(last_executions, int(row.get("executions", 0)))
            except (TypeError, ValueError):
                pass
    return {
        "max_covered_edges": max_edges,
        "last_executions": last_executions,
        "last_sample": last,
    }


def read_telemetry(out_dir: Path) -> list[dict[str, Any]]:
    path = out_dir / "telemetry" / "run_telemetry.jsonl"
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def find_fuzz_dir(out_dir: Path) -> Path | None:
    dirs = sorted(p for p in out_dir.glob("fuzz-*") if p.is_dir())
    return dirs[-1] if dirs else None


def count_files(path: Path | None) -> int:
    if path is None or not path.is_dir():
        return 0
    return sum(1 for p in path.iterdir() if p.is_file() and not p.name.startswith("."))


def pcap_records(path: Path) -> int:
    if not path.is_file():
        return 0
    data = path.read_bytes()
    if len(data) < 24:
        return 0
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    offset = 24
    count = 0
    while offset + 16 <= len(data):
        incl_len = struct.unpack_from(endian + "I", data, offset + 8)[0]
        offset += 16 + incl_len
        count += 1
    return count


def summarise(out_dir: Path, case: dict[str, Any], backend: str, seconds: int, preset: str, binary: Path) -> dict[str, Any]:
    fuzz_dir = find_fuzz_dir(out_dir)
    queue = fuzz_dir / "queue" if fuzz_dir else None
    crashes = fuzz_dir / "crashes" if fuzz_dir else None
    coverage = read_coverage(out_dir)
    telemetry = read_telemetry(out_dir)
    first_run = telemetry[0] if telemetry else {}
    states = {flag: bool(any(row.get(flag) for row in telemetry)) for flag in STATE_FLAGS}
    summary = {
        "case": case["case"],
        "backend": backend,
        "preset": preset,
        "seconds": seconds,
        "binary": str(binary),
        "fuzz_dir": str(fuzz_dir) if fuzz_dir else None,
        "corpus_size": count_files(queue),
        "objective_size": count_files(crashes),
        "max_covered_edges": coverage.get("max_covered_edges", 0),
        "executions": coverage.get("last_executions", len(telemetry)),
        "states_seed_run": {flag: bool(first_run.get(flag)) for flag in STATE_FLAGS},
        "states_any_run": states,
        "max_semantic_probes": max((row.get("semantic_probe_sent", 0) for row in telemetry), default=0),
        "max_known_handles": max((row.get("known_handle_count_end_of_run", 0) for row in telemetry), default=0),
        "telemetry_runs": len(telemetry),
        "log": str(out_dir / "run.log"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def print_summary(summary: dict[str, Any]) -> None:
    print(f"case            : {summary['case']} ({summary['backend']}, preset={summary['preset']})")
    print(f"runtime         : {summary['seconds']}s")
    print(f"corpus          : {summary['corpus_size']} inputs")
    print(f"objectives      : {summary['objective_size']} crashes")
    print(f"max edges       : {summary['max_covered_edges']}")
    print(f"semantic probes : {summary['max_semantic_probes']}")
    print(f"known handles   : {summary['max_known_handles']}")
    reached = [k for k, v in summary["states_seed_run"].items() if v]
    print(f"seed-run states : {', '.join(reached) if reached else '(none)'}")
    print(f"summary         : {summary['log'].rsplit('/', 1)[0]}/summary.json")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def command_list(_: argparse.Namespace) -> int:
    print(f"{'CASE':<40} {'BACKEND':<10} {'PAPER':<10}")
    print("-" * 62)
    for case in discover_cases():
        paper = {
            "01_btstack_sm_pairing_central": "RQ1/RQ3",
            "02_btstack_mesh_node": "RQ1/RQ3",
            "03_btstack_le_mitm": "RQ1/RQ3",
            "04_esp32_bluedroid_gatt_client": "RQ1",
            "05_esp32_nimble_gattc_gatts_coex": "RQ1/RQ3",
            "06_nrf52_zephyr_gatt_write": "RQ1/RQ3",
            "07_zephyr_hr_central_native": "RQ1",
        }.get(case["case"], "-")
        print(f"{case['case']:<40} {case['backend']:<10} {paper:<10}")
    return 0


def command_run(args: argparse.Namespace) -> int:
    case = select_case(args)
    backend = case["backend"]
    binary = resolve_binary(backend)
    out_dir = Path(args.output).resolve() if args.output else DEFAULT_OUTPUT / f"{time.strftime('%Y%m%d-%H%M%S')}_{case['case']}"
    config_path, _ = prepare_run(
        case,
        out_dir,
        args.preset,
        keep_telemetry=not args.no_telemetry,
        instance=args.instance,
    )
    print(f"[hostfuzz] case={case['case']} backend={backend} seconds={args.seconds}")
    print(f"[hostfuzz] output={out_dir}")
    returncode = run_binary(
        binary,
        ["-f", "-l", args.log_level, str(config_path)],
        out_dir,
        out_dir / "run.log",
        args.seconds,
    )
    summary = summarise(out_dir, case, backend, args.seconds, args.preset, binary)
    summary["fuzzer_returncode"] = returncode
    print_summary(summary)
    if summary["fuzz_dir"] is None:
        print("[hostfuzz] ERROR: the fuzzer did not create a work directory; see run.log", file=sys.stderr)
        return 2
    return 0


def command_replay(args: argparse.Namespace) -> int:
    case = select_case(args)
    backend = case["backend"]
    binary = resolve_binary(backend)
    out_dir = Path(args.output).resolve() if args.output else DEFAULT_OUTPUT / f"{time.strftime('%Y%m%d-%H%M%S')}_{case['case']}_replay"
    config_path, _ = prepare_run(
        case,
        out_dir,
        "full",
        keep_telemetry=False,
        instance=args.instance,
    )
    input_path = Path(args.input).resolve()
    if not input_path.is_file():
        raise SystemExit(f"input not found: {input_path}")
    pcap_path = out_dir / "replay.pcap"
    print(f"[hostfuzz] replay {case['case']} input={input_path}")
    returncode = run_binary(
        binary,
        ["-r", "-l", args.log_level, str(config_path), str(input_path), str(pcap_path)],
        out_dir,
        out_dir / "replay.log",
        300,
    )
    records = pcap_records(pcap_path)
    result = {
        "case": case["case"],
        "backend": backend,
        "input": str(input_path),
        "pcap": str(pcap_path),
        "hci_records": records,
        "returncode": returncode,
    }
    (out_dir / "replay.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"hci records : {records}")
    print(f"pcap        : {pcap_path}")
    return 0 if pcap_path.is_file() else 1


def command_paper(_: argparse.Namespace) -> int:
    print(
        """Paper-to-code map
=================
RQ1 (effectiveness)   experiments/run_rq1.py  -> outputs/RQ1/<timestamp>/
RQ3 (ablation)        experiments/run_rq3.py  -> outputs/RQ3/<timestamp>/
Backends                     usermode (QEMU user) / esp32 (QEMU system) / fuzzware / src (native)
"""
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HostFuzz demo runner")
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="list demo cases")
    listing.set_defaults(func=command_list)

    run = sub.add_parser("run", help="run a short fuzzing campaign")
    run_target = run.add_mutually_exclusive_group(required=True)
    run_target.add_argument("--case", help="bundled demo case name")
    run_target.add_argument("--config", help="path to any HostFuzz case YAML")
    run.add_argument("--name", default="", help="label for --config runs")
    run.add_argument("--instance", default="", help="unique instance suffix (parallel runs)")
    run.add_argument("--seconds", type=int, default=60)
    run.add_argument("--output", default="")
    run.add_argument("--preset", default="full", choices=["full", "m1_m2", "m1_only", "hci_random_floor"])
    run.add_argument("--log-level", default="warn")
    run.add_argument("--no-telemetry", action="store_true")
    run.set_defaults(func=command_run)

    replay = sub.add_parser("replay", help="replay one input and dump a pcap")
    replay_target = replay.add_mutually_exclusive_group(required=True)
    replay_target.add_argument("--case", help="bundled demo case name")
    replay_target.add_argument("--config", help="path to any HostFuzz case YAML")
    replay.add_argument("--name", default="", help="label for --config runs")
    replay.add_argument("--instance", default="", help="unique instance suffix (parallel runs)")
    replay.add_argument("--input", required=True, help="MetaInput corpus file to replay")
    replay.add_argument("--output", default="")
    replay.add_argument("--log-level", default="warn")
    replay.set_defaults(func=command_replay)

    paper = sub.add_parser("paper", help="show paper-to-code mapping")
    paper.set_defaults(func=command_paper)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
