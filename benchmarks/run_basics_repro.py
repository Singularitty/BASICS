#!/usr/bin/env python3
"""Reproduce BASICS benchmark preparation and runner commands.

This script is intentionally a thin orchestrator over the repository's existing
benchmark scripts. It keeps the committed benchmark selection in this directory
and writes per-run command logs under Benchmarks/reproducibility/.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = Path(__file__).resolve().parent
DEFAULT_OSS_MANIFEST = BUNDLE / "oss_projects.json"
DEFAULT_PACKAGE_MANIFEST = BUNDLE / "linux_packages.json"
RUNS_ROOT = ROOT / "Benchmarks" / "reproducibility"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def shell_join(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


class Runner:
    def __init__(self, run_dir: Path, dry_run: bool) -> None:
        self.run_dir = run_dir
        self.dry_run = dry_run
        self.command_log = run_dir / "commands.log"
        run_dir.mkdir(parents=True, exist_ok=True)
        self.command_log.write_text("", encoding="utf-8")

    def run(self, cmd: list[str], *, env: dict[str, str] | None = None) -> None:
        line = shell_join(cmd)
        if env:
            exported = " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(env.items()))
            line = f"{exported} {line}"
        with self.command_log.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        print(f"$ {line}", flush=True)
        if self.dry_run:
            return
        next_env = os.environ.copy()
        if env:
            next_env.update(env)
        subprocess.run(cmd, cwd=ROOT, env=next_env, check=True)


def write_run_metadata(run_dir: Path, args: argparse.Namespace, oss_manifest: Path, package_manifest: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    serializable_args = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in vars(args).items()
    }
    metadata = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_head": git_head(),
        "cwd": str(ROOT),
        "python": sys.version,
        "platform": platform.platform(),
        "argv": sys.argv,
        "args": serializable_args,
        "oss_manifest": rel(oss_manifest),
        "package_manifest": rel(package_manifest),
    }
    (run_dir / "environment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    for path in (oss_manifest, package_manifest):
        if path.exists():
            (run_dir / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def selected_projects(config: dict[str, Any], requested: list[str]) -> list[str]:
    known = [project["name"] for project in config.get("projects", [])]
    if not requested:
        return known
    selected: list[str] = []
    for value in requested:
        selected.extend(part.strip() for part in value.split(",") if part.strip())
    unknown = [name for name in selected if name not in known]
    if unknown:
        raise SystemExit(f"Unknown OSS project(s): {', '.join(unknown)}. Known: {', '.join(known)}")
    return list(dict.fromkeys(selected))


def selected_packages(config: dict[str, Any], requested_groups: list[str], requested_packages: list[str]) -> list[str]:
    groups: dict[str, list[str]] = config.get("groups", {})
    selected: list[str] = []
    group_names = requested_groups or ["core", "additional"]
    for group in group_names:
        if group == "all":
            for values in groups.values():
                selected.extend(values)
            continue
        if group not in groups:
            raise SystemExit(f"Unknown package group {group!r}. Known: {', '.join(groups)}")
        selected.extend(groups[group])
    for value in requested_packages:
        selected.extend(part.strip() for part in value.split(",") if part.strip())
    return list(dict.fromkeys(selected))


def prepare_stack(runner: Runner, args: argparse.Namespace) -> None:
    cmd = [
        "python3",
        "scripts/prepare_external_benchmarks.py",
        "--workers",
        str(args.prep_workers),
        "--timeout-sec",
        str(args.prepare_timeout_sec),
    ]
    if args.force:
        cmd.append("--force")
    runner.run(cmd)


def run_stack(runner: Runner, args: argparse.Namespace) -> None:
    cmd = [
        "scripts/run_compiled_stack_benchmarks.sh",
        "all",
        "--timeout",
        str(args.stack_timeout_sec),
        "--cfg-mode",
        "fast",
        "--simulation",
        "static",
    ]
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    runner.run(cmd)


def prepare_oss(runner: Runner, args: argparse.Namespace, config: dict[str, Any]) -> None:
    projects = selected_projects(config, args.oss_project)
    output_manifest = config.get("output_manifest", "Benchmarks/opensource/opensource_cases.json")
    function_manifest = config.get("function_manifest", "Benchmarks/opensource/opensource_function_cases_repro.json")
    max_binaries = int(config.get("max_binaries_per_project", 25))

    runner.run(
        [
            "python3",
            "scripts/setup_opensource_benchmarks.py",
            "--project",
            ",".join(projects),
            "--keep-going",
            "--jobs",
            str(args.build_jobs),
            "--timeout-sec",
            str(args.prepare_timeout_sec),
            "--max-binaries-per-project",
            str(max_binaries),
            "--out",
            output_manifest,
        ]
        + (["--update"] if args.update else [])
    )

    function_cfg = config.get("function_sweep", {})
    cmd = [
        "python3",
        "scripts/prepare_opensource_function_manifest.py",
        "--manifest",
        output_manifest,
        "--out",
        function_manifest,
    ]
    if function_cfg.get("include_main", True):
        cmd.append("--include-main")
    if function_cfg.get("all_symbols", True):
        cmd.append("--all-symbols")
    max_functions = function_cfg.get("max_functions_per_binary")
    if max_functions is not None:
        cmd.extend(["--max-functions-per-binary", str(max_functions)])
    runner.run(cmd)


def run_oss(runner: Runner, args: argparse.Namespace, config: dict[str, Any]) -> None:
    function_manifest = config.get("function_manifest", "Benchmarks/opensource/opensource_function_cases_repro.json")
    sweep_cfg = config.get("function_sweep", {})
    cmd = [
        "python3",
        "scripts/run_opensource_low_memory_function_sweep.py",
        "--manifest",
        function_manifest,
        "--workers",
        str(args.workers or sweep_cfg.get("workers", 8)),
        "--timeout-sec",
        str(args.timeout_sec or sweep_cfg.get("timeout_sec", 240)),
        "--memory-limit-mb",
        str(sweep_cfg.get("memory_limit_mb", 2500)),
        "--concolic-step-limit",
        str(sweep_cfg.get("concolic_step_limit", 100)),
        "--concolic-active-limit",
        str(sweep_cfg.get("concolic_active_limit", 16)),
        "--max-states",
        str(sweep_cfg.get("max_states", 5000)),
    ]
    hard_limit = sweep_cfg.get("hard_memory_limit_mb")
    if hard_limit is not None:
        cmd.extend(["--hard-memory-limit-mb", str(hard_limit)])
    if sweep_cfg.get("cfg_skip_loopfinder", False):
        cmd.append("--cfg-skip-loopfinder")
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    runner.run(cmd)


def write_package_list(run_dir: Path, packages: list[str]) -> Path:
    path = run_dir / "linux_packages.selected.txt"
    path.write_text("\n".join(packages) + "\n", encoding="utf-8")
    return path


def prepare_linux(runner: Runner, args: argparse.Namespace, config: dict[str, Any]) -> None:
    packages = selected_packages(config, args.package_group, args.package)
    package_list = write_package_list(runner.run_dir, packages)
    runner.run(
        [
            "python3",
            "scripts/setup_linux_repo_binaries.py",
            "--package",
            str(package_list),
            "--keep-going",
            "--timeout-sec",
            str(args.prepare_timeout_sec),
            "--max-binaries-per-package",
            str(config.get("max_binaries_per_package", 20)),
            "--max-binary-size-mb",
            str(config.get("max_binary_size_mb", 25)),
            "--out",
            config.get("output_manifest", "Benchmarks/linux_repos/linux_repo_binary_cases.json"),
        ]
    )


def run_linux(runner: Runner, args: argparse.Namespace, config: dict[str, Any]) -> None:
    scan_cfg = config.get("all_function_scan", {})
    cmd = [
        "python3",
        "scripts/run_opensource_all_function_scan.py",
        "--manifest",
        config.get("output_manifest", "Benchmarks/linux_repos/linux_repo_binary_cases.json"),
        "--workers",
        str(args.workers or scan_cfg.get("workers", 4)),
        "--timeout-sec",
        str(args.timeout_sec or scan_cfg.get("timeout_sec", 600)),
        "--scan-memory-limit-mb",
        str(scan_cfg.get("scan_memory_limit_mb", 3000)),
        "--concolic-step-limit",
        str(scan_cfg.get("concolic_step_limit", 100)),
        "--scan-arg-stack-guard-bytes",
        str(scan_cfg.get("scan_arg_stack_guard_bytes", "0x200000")),
    ]
    hard_limit = scan_cfg.get("hard_memory_limit_mb")
    if hard_limit is not None:
        cmd.extend(["--hard-memory-limit-mb", str(hard_limit)])
    if scan_cfg.get("scan_constrain_arg_regs", False):
        cmd.append("--scan-constrain-arg-regs")
    if scan_cfg.get("scan_include_runtime_symbols", False):
        cmd.append("--scan-include-runtime-symbols")
    if scan_cfg.get("scan_confirm_callers", True):
        cmd.append("--scan-confirm-callers")
    if scan_cfg.get("scan_confirm_max_callers") is not None:
        cmd.extend(["--scan-confirm-max-callers", str(scan_cfg["scan_confirm_max_callers"])])
    if scan_cfg.get("scan_skip_loopfinder", False):
        cmd.append("--scan-skip-loopfinder")
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    runner.run(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare and run reproducible BASICS benchmark suites.")
    parser.add_argument("--suite", choices=["stack", "oss", "linux", "all"], default="all")
    parser.add_argument("--phase", choices=["prepare", "run", "all"], default="all")
    parser.add_argument("--oss-manifest", type=Path, default=DEFAULT_OSS_MANIFEST)
    parser.add_argument("--package-manifest", type=Path, default=DEFAULT_PACKAGE_MANIFEST)
    parser.add_argument("--oss-project", action="append", default=[], help="OSS project name or comma-list; default uses the manifest.")
    parser.add_argument("--package-group", action="append", default=[], help="Package group from linux_packages.json; default is core+additional.")
    parser.add_argument("--package", action="append", default=[], help="Extra package name or comma-list.")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--workers", type=int, default=None, help="Analysis workers for OSS/Linux run phases.")
    parser.add_argument("--build-jobs", type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument("--prep-workers", type=int, default=min(os.cpu_count() or 1, 16))
    parser.add_argument("--prepare-timeout-sec", type=int, default=900)
    parser.add_argument("--stack-timeout-sec", type=int, default=180)
    parser.add_argument("--timeout-sec", type=int, default=None, help="OSS/Linux per-binary or per-function timeout override.")
    parser.add_argument("--limit", type=int, default=None, help="Limit cases during run phases for smoke tests.")
    parser.add_argument("--force", action="store_true", help="Force recompilation during stack preparation.")
    parser.add_argument("--update", action="store_true", help="git pull existing OSS clones before building.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS_ROOT / run_id
    oss_config = load_json(args.oss_manifest)
    package_config = load_json(args.package_manifest)
    write_run_metadata(run_dir, args, args.oss_manifest, args.package_manifest)
    runner = Runner(run_dir, args.dry_run)

    suites = ["stack", "oss", "linux"] if args.suite == "all" else [args.suite]
    do_prepare = args.phase in {"prepare", "all"}
    do_run = args.phase in {"run", "all"}

    if "stack" in suites and do_prepare:
        prepare_stack(runner, args)
    if "stack" in suites and do_run:
        run_stack(runner, args)

    if "oss" in suites and do_prepare:
        prepare_oss(runner, args, oss_config)
    if "oss" in suites and do_run:
        run_oss(runner, args, oss_config)

    if "linux" in suites and do_prepare:
        prepare_linux(runner, args, package_config)
    if "linux" in suites and do_run:
        run_linux(runner, args, package_config)

    print(f"\nReproducibility log: {rel(run_dir)}")
    print(f"Commands: {rel(runner.command_log)}")


if __name__ == "__main__":
    main()
