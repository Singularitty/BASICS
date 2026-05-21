#!/usr/bin/env python3
"""Clone/build selected open-source projects and emit a BASICS manifest.

The manifest is intentionally unlabeled: these are real project binaries, not
ground-truth benchmark cases. Timeouts/errors should be treated as coverage
failures, while findings need manual triage.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "Benchmarks" / "opensource"
DEFAULT_MANIFEST = BASE / "opensource_cases.json"


@dataclass(frozen=True)
class Project:
    name: str
    repo: str
    build: tuple[tuple[str, ...], ...]
    description: str


PROJECTS: dict[str, Project] = {
    "soem": Project(
        name="soem",
        repo="https://github.com/OpenEtherCATsociety/SOEM.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="Simple Open EtherCAT Master; small CPS/fieldbus examples.",
    ),
    "canopennode": Project(
        name="canopennode",
        repo="https://github.com/CANopenNode/CANopenNode.git",
        build=(
            ("make", "-C", "example", "all", "-j1"),
        ),
        description="CANopen protocol stack; embedded/CPS-oriented C code.",
    ),
    "open62541": Project(
        name="open62541",
        repo="https://github.com/open62541/open62541.git",
        build=(
            (
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DUA_BUILD_EXAMPLES=ON",
                "-DUA_BUILD_UNIT_TESTS=OFF",
            ),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="OPC UA implementation with example server/client binaries.",
    ),
    "libplctag": Project(
        name="libplctag",
        repo="https://github.com/libplctag/libplctag.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="PLC tag communication library with examples/tests.",
    ),
    "lib60870": Project(
        name="lib60870",
        repo="https://github.com/mz-automation/lib60870.git",
        build=(
            ("cmake", "-S", "lib60870-C", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="IEC 60870-5-101/104 protocol library and examples.",
    ),
    "libiec61850": Project(
        name="libiec61850",
        repo="https://github.com/mz-automation/libiec61850.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="IEC 61850/MMS library used in substation automation.",
    ),
    "libmodbus": Project(
        name="libmodbus",
        repo="https://github.com/stephane/libmodbus.git",
        build=(
            ("./autogen.sh",),
            ("./configure", "--enable-static=no", "CFLAGS=-g -O0 -fno-omit-frame-pointer"),
            ("make", "-j{jobs}"),
        ),
        description="Modbus protocol library with tests and utilities.",
    ),
    "mosquitto": Project(
        name="mosquitto",
        repo="https://github.com/eclipse-mosquitto/mosquitto.git",
        build=(
            (
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DWITH_DOCS=OFF",
                "-DWITH_TLS=OFF",
                "-DWITH_CJSON=ON",
            ),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="MQTT broker/client implementation in C.",
    ),
    "libuv": Project(
        name="libuv",
        repo="https://github.com/libuv/libuv.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug", "-DBUILD_TESTING=ON"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="Cross-platform asynchronous I/O library with test binaries.",
    ),
    "mbedtls": Project(
        name="mbedtls",
        repo="https://github.com/Mbed-TLS/mbedtls.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug", "-DENABLE_TESTING=ON", "-DENABLE_PROGRAMS=ON"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="TLS/crypto library with command-line programs and tests.",
    ),
    "libyaml": Project(
        name="libyaml",
        repo="https://github.com/yaml/libyaml.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug", "-DBUILD_TESTING=ON"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="YAML parser/emitter library and tests.",
    ),
    "cjson": Project(
        name="cjson",
        repo="https://github.com/DaveGamble/cJSON.git",
        build=(
            ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug", "-DENABLE_CJSON_TEST=ON"),
            ("cmake", "--build", "build", "--parallel", "{jobs}"),
        ),
        description="Small C JSON parser with test binaries.",
    ),
}


def run(cmd: list[str], cwd: Path, timeout_sec: int | None) -> None:
    print(f"+ ({cwd.relative_to(ROOT)}) {' '.join(cmd)}", flush=True)
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout[-4000:])
        raise RuntimeError(f"command failed with exit {proc.returncode}: {' '.join(cmd)}")


def clone_or_update(project: Project, project_dir: Path, timeout_sec: int | None, update: bool) -> None:
    if project_dir.exists():
        if update:
            run(["git", "-C", str(project_dir), "pull", "--ff-only"], ROOT, timeout_sec)
        return
    project_dir.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--depth", "1", project.repo, str(project_dir)], ROOT, timeout_sec)


def build_project(project: Project, project_dir: Path, jobs: int, timeout_sec: int | None) -> None:
    for raw_cmd in project.build:
        cmd = [part.format(jobs=jobs) for part in raw_cmd]
        run(cmd, project_dir, timeout_sec)


def is_elf_executable(path: Path) -> bool:
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            return False
        with path.open("rb") as f:
            if f.read(4) != b"\x7fELF":
                return False
        return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def discover_binaries(project_dir: Path) -> list[Path]:
    skip_dirs = {".git", ".github", "__pycache__", "CMakeFiles"}
    skip_names = {"a.out"}
    binaries: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        current = Path(dirpath)
        for name in filenames:
            if name in skip_names:
                continue
            path = current / name
            if is_elf_executable(path):
                binaries.append(path)
    return sorted(binaries)


def build_manifest(selected: list[Project], max_binaries_per_project: int | None, failures: dict[str, str] | None = None) -> dict:
    cases = []
    for project in selected:
        project_dir = BASE / "src" / project.name
        binaries = discover_binaries(project_dir)
        if max_binaries_per_project is not None:
            binaries = binaries[:max_binaries_per_project]
        for idx, binary in enumerate(binaries, start=1):
            rel = binary.relative_to(ROOT)
            case_id = f"opensource_{project.name}_{idx:04d}_{binary.name}"
            cases.append(
                {
                    "case_id": case_id,
                    "dataset": f"opensource/{project.name}",
                    "true_present_vuln": "",
                    "label_confidence": "unlabeled",
                    "label_rule": "real_project_unlabeled",
                    "source_path": "",
                    "binary_path": str(rel),
                    "compile": {"required": False},
                    "project": project.name,
                    "project_repo": project.repo,
                    "project_description": project.description,
                }
            )
    return {
        "generated_by": "scripts/setup_opensource_benchmarks.py",
        "note": "Unlabeled real-project binaries for BASICS smoke/triage runs.",
        "setup_failures": failures or {},
        "cases": cases,
    }


def parse_projects(values: list[str]) -> list[Project]:
    if not values or values == ["all"]:
        keys = list(PROJECTS)
    else:
        keys = []
        for value in values:
            keys.extend(part.strip() for part in value.split(",") if part.strip())
    unknown = [key for key in keys if key not in PROJECTS]
    if unknown:
        raise SystemExit(f"Unknown project(s): {', '.join(unknown)}. Known: {', '.join(PROJECTS)}")
    return [PROJECTS[key] for key in keys]


def main() -> None:
    parser = argparse.ArgumentParser(description="Set up open-source CPS-ish binaries for BASICS.")
    parser.add_argument(
        "--project",
        action="append",
        default=[],
        help=f"Project name or comma-list. Defaults to all. Known: {', '.join(PROJECTS)}",
    )
    parser.add_argument("--list-projects", action="store_true")
    parser.add_argument("--skip-clone", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep-going", action="store_true", help="Continue when a clone/build fails and record the failure in the manifest.")
    parser.add_argument("--update", action="store_true", help="git pull existing clones before building.")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument("--max-binaries-per-project", type=int, default=None)
    parser.add_argument("--out", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    if args.list_projects:
        for project in PROJECTS.values():
            print(f"{project.name:12} {project.repo}")
            print(f"  {project.description}")
        return

    if shutil.which("git") is None and not args.skip_clone:
        raise SystemExit("git is required unless --skip-clone is used")
    if shutil.which("cmake") is None and not args.skip_build:
        raise SystemExit("cmake is required unless --skip-build is used")

    selected = parse_projects(args.project)
    BASE.mkdir(parents=True, exist_ok=True)

    failures: dict[str, str] = {}
    for project in selected:
        project_dir = BASE / "src" / project.name
        print(f"\n== {project.name} ==", flush=True)
        try:
            if not args.skip_clone:
                clone_or_update(project, project_dir, args.timeout_sec, args.update)
            if not args.skip_build:
                build_project(project, project_dir, args.jobs, args.timeout_sec)
        except Exception as exc:
            failures[project.name] = str(exc)
            print(f"!! {project.name} failed: {exc}", flush=True)
            if not args.keep_going:
                raise

    manifest = build_manifest(selected, args.max_binaries_per_project, failures)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for case in manifest["cases"]:
        project = case["project"]
        counts[project] = counts.get(project, 0) + 1
    print(f"\nWrote {len(manifest['cases'])} cases to {args.out.relative_to(ROOT)}")
    for project, count in sorted(counts.items()):
        print(f"  {project}: {count}")
    if failures:
        print("\nFailures:")
        for project, reason in sorted(failures.items()):
            print(f"  {project}: {reason}")


if __name__ == "__main__":
    main()
