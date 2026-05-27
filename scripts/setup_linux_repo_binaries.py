#!/usr/bin/env python3
"""Download apt repository packages, extract ELF executables, and emit a BASICS manifest.

This is intentionally binary-first. Distro packages are usually stripped, so
function-entry symbol manifests are often sparse; use BASICS --scan-all-functions
over these binaries instead.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "Benchmarks" / "linux_repos"
DEFAULT_OUT = BASE / "linux_repo_binary_cases.json"
DEFAULT_PACKAGES = (
    "bash",
    "coreutils",
    "findutils",
    "grep",
    "sed",
    "gawk",
    "tar",
    "gzip",
    "bzip2",
    "xz-utils",
    "util-linux",
    "procps",
    "iproute2",
    "iputils-ping",
    "curl",
    "wget",
    "openssh-client",
    "rsync",
    "sqlite3",
    "jq",
    "git",
)


def run(cmd: list[str], cwd: Path, timeout_sec: int | None) -> subprocess.CompletedProcess[str]:
    print(f"+ ({cwd.relative_to(ROOT)}) {' '.join(cmd)}", flush=True)
    return subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_sec,
        check=False,
    )


def is_elf_executable(path: Path, max_size_mb: int | None) -> bool:
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            return False
        if max_size_mb is not None and st.st_size > max_size_mb * 1024 * 1024:
            return False
        with path.open("rb") as f:
            if f.read(4) != b"\x7fELF":
                return False
        return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def discover_binaries(root: Path, max_size_mb: int | None, max_binaries: int | None) -> list[Path]:
    search_roots = [root / "usr" / "bin", root / "usr" / "sbin", root / "bin", root / "sbin"]
    binaries: list[Path] = []
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(search_root):
            dirnames[:] = [d for d in dirnames if d not in {".debug", "__pycache__"}]
            for name in filenames:
                path = Path(dirpath) / name
                if is_elf_executable(path, max_size_mb):
                    binaries.append(path)
    binaries = sorted(set(binaries))
    if max_binaries is not None:
        binaries = binaries[:max_binaries]
    return binaries


def package_version(package: str) -> str:
    proc = subprocess.run(
        ["apt-cache", "policy", package],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Candidate:"):
            return stripped.split(":", 1)[1].strip()
    return ""


def safe_id(text: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text).strip("_")


def parse_packages(values: list[str]) -> list[str]:
    if not values:
        return list(DEFAULT_PACKAGES)
    packages: list[str] = []
    for value in values:
        if value == "default":
            packages.extend(DEFAULT_PACKAGES)
        elif Path(value).exists():
            packages.extend(
                line.strip()
                for line in Path(value).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        else:
            packages.extend(part.strip() for part in value.split(",") if part.strip())
    return list(dict.fromkeys(packages))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a BASICS manifest from apt repository binaries.")
    parser.add_argument("--package", action="append", default=[], help="Package name, comma-list, 'default', or a file of package names.")
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument("--max-binaries-per-package", type=int, default=20)
    parser.add_argument("--max-binary-size-mb", type=int, default=25)
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--keep-going", action="store_true")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    if shutil.which("apt-get") is None or shutil.which("dpkg-deb") is None:
        raise SystemExit("apt-get and dpkg-deb are required")

    packages = parse_packages(args.package)
    deb_dir = BASE / "debs"
    extract_dir = BASE / "extracted"
    deb_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    failures: dict[str, str] = {}
    cases = []
    for package in packages:
        package_id = safe_id(package)
        package_extract = extract_dir / package_id
        print(f"\n== {package} ==", flush=True)
        try:
            if not args.skip_download:
                before = set(deb_dir.glob("*.deb"))
                proc = run(["apt-get", "download", package], deb_dir, args.timeout_sec)
                if proc.returncode != 0:
                    sys.stdout.write(proc.stdout[-4000:])
                    raise RuntimeError(f"apt-get download failed with exit {proc.returncode}")
                after = set(deb_dir.glob("*.deb"))
                debs = sorted(after - before) or sorted(deb_dir.glob(f"{package_id}_*.deb"))
            else:
                debs = sorted(deb_dir.glob(f"{package_id}_*.deb"))
            if not debs:
                raise RuntimeError("no .deb downloaded/found")
            package_extract.mkdir(parents=True, exist_ok=True)
            for deb in debs:
                proc = run(["dpkg-deb", "-x", str(deb), str(package_extract)], ROOT, args.timeout_sec)
                if proc.returncode != 0:
                    sys.stdout.write(proc.stdout[-4000:])
                    raise RuntimeError(f"dpkg-deb failed for {deb.name} with exit {proc.returncode}")

            binaries = discover_binaries(package_extract, args.max_binary_size_mb, args.max_binaries_per_package)
            version = package_version(package)
            for index, binary in enumerate(binaries, start=1):
                rel = binary.relative_to(ROOT)
                cases.append(
                    {
                        "case_id": f"linuxrepo_{package_id}_{index:04d}_{safe_id(binary.name)}",
                        "dataset": f"linux_repo/{package}",
                        "true_present_vuln": "",
                        "label_confidence": "unlabeled",
                        "label_rule": "linux_repo_binary_unlabeled",
                        "source_path": "",
                        "binary_path": str(rel),
                        "compile": {"required": False},
                        "project": package,
                        "project_repo": "apt",
                        "project_description": f"Ubuntu apt package {package} {version}".strip(),
                        "package": package,
                        "package_version": version,
                    }
                )
            print(f"  binaries: {len(binaries)}", flush=True)
        except Exception as exc:
            failures[package] = str(exc)
            print(f"!! {package} failed: {exc}", flush=True)
            if not args.keep_going:
                raise

    manifest = {
        "generated_by": "scripts/setup_linux_repo_binaries.py",
        "note": "Unlabeled ELF executables extracted from Ubuntu apt packages; intended for --scan-all-functions.",
        "packages": packages,
        "setup_failures": failures,
        "cases": cases,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nWrote {len(cases)} binary cases to {args.out.relative_to(ROOT)}")
    counts: dict[str, int] = {}
    for case in cases:
        counts[case["package"]] = counts.get(case["package"], 0) + 1
    for package, count in sorted(counts.items()):
        print(f"  {package}: {count}")
    if failures:
        print("\nFailures:")
        for package, reason in sorted(failures.items()):
            print(f"  {package}: {reason}")


if __name__ == "__main__":
    main()
