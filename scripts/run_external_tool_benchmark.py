#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import signal
import shutil
import subprocess
import time
import shlex
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.environ.get("BASICS_BENCH_ROOT", Path(__file__).resolve().parents[1])).resolve()
DEFAULT_MANIFEST = ROOT / "Benchmarks" / "stack_benchmark" / "stack_cases_combined.json"
RESULTS_DIR = ROOT / "Benchmarks" / "stack_benchmark" / "external_results"
COMPILE_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
CODEQL_DEFAULT_QUERY = "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls"
CODEQL_EXTRA_QUERIES = (
    ROOT
    / "tools"
    / "codeql"
    / "qlpacks"
    / "codeql"
    / "cpp-queries"
    / "1.6.2"
    / "Security"
    / "CWE"
    / "CWE-129"
    / "ImproperArrayIndexValidation.ql",
)

CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{2,4})\b", re.IGNORECASE)
CWE_CHECKER_BO_IDS = {"119", "787"}
CWE_CHECKER_PAPER_IDS = {"119", "676", "787"}
BO_CWE_IDS = {
    "119", "120", "121", "122", "123", "124", "125", "126", "127",
    "129", "130", "131", "193", "680", "787", "788", "805", "806",
}
MEMCHECK_RE = re.compile(
    r"Invalid (?:read|write)|Jump to the invalid address|Address .* is not stack|"
    r"Process terminating with default action of signal 11|stack overflow|stack smashing|"
    r"SIGSEGV|segmentation fault|ERROR SUMMARY:\s*[1-9]\d* errors",
    re.IGNORECASE,
)
BAI_RE = re.compile(r"\b(?:CWE119|CWE125|CWE676|CWE787)\b|\bOut[- ]of[- ]bounds\b|\bBuffer Overflow\b", re.IGNORECASE)
MANTICORE_RE = re.compile(r"\b(crash|crashed|SIGSEGV|segmentation fault|invalid memory|memory violation)\b", re.IGNORECASE)
MANTICORE_INFRA_RE = re.compile(
    r"version [`']GLIBC_[^`']+[`'] not found|"
    r"No such file or directory|"
    r"error while loading shared libraries",
    re.IGNORECASE,
)
ARBITER_REPORTS_RE = re.compile(r"^ARBITER_REPORTS:\s*([1-9]\d*)\b", re.MULTILINE)


def load_cases(path: Path):
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, list):
        return obj
    if "datasets" in obj:
        cases = []
        for data in obj["datasets"].values():
            cases.extend(data.get("cases", []))
        return cases
    if "cases" in obj:
        return obj["cases"]
    raise ValueError(f"Unsupported manifest format: {path}")


def parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def resolve_juliet_individual_binary(path: Path):
    if path.suffix != ".out":
        return None
    match = re.match(r"^(.*)_(\d+?)_(bad|goodB2G|goodG2B|good)$", path.stem, re.IGNORECASE)
    if not match:
        return None
    candidate = path.with_name(f"{match.group(1)}_{match.group(2)}.out")
    return candidate if candidate.exists() else None


def ensure_binary(case, compile_missing=False):
    binary_path = case.get("binary_path")
    if not binary_path:
        return None, "missing_binary_path"
    binary = ROOT / binary_path
    if binary.exists():
        return binary, None
    if not compile_missing:
        return None, f"binary_missing:{binary}"
    compile_info = case.get("compile", {})
    if not parse_bool(compile_info.get("required", False)):
        return None, f"binary_missing:{binary}"
    cmd = compile_info.get("command") or []
    if not cmd:
        return None, "compile_command_missing"
    with COMPILE_LOCK:
        if binary.exists():
            return binary, None
        alt = resolve_juliet_individual_binary(binary)
        if alt is not None:
            return alt, None
        binary.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if proc.returncode != 0:
            return None, f"compile_failed:{proc.stdout[-800:]}"
        if binary.exists():
            return binary, None
        alt = resolve_juliet_individual_binary(binary)
        if alt is not None:
            return alt, None
    return None, "compile_finished_binary_missing"


def terminate_process_group(proc):
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


def run_interruptible(cmd, timeout_sec, stdin_text=None, cwd=None, env=None):
    proc = subprocess.Popen(
        cmd,
        cwd=cwd or ROOT,
        env=env,
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = proc.communicate(stdin_text, timeout=timeout_sec)
        return proc.returncode, output or "", None
    except subprocess.TimeoutExpired:
        terminate_process_group(proc)
        output, _ = proc.communicate(timeout=5)
        return proc.returncode, output or "", "timeout"


def have_exe(name):
    return subprocess.run(["bash", "-lc", f"command -v {name}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def docker_image_exists(image):
    if not have_exe("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def docker_mount_for(binary):
    parent = binary.parent.resolve()
    return str(parent), f"/work/{binary.name}"


def source_path_for(case):
    source = case.get("analysis_source_path") or case.get("source_path")
    if not source:
        return None, "missing_source_path"
    path = ROOT / source
    if not path.exists():
        return None, f"source_missing:{path}"
    return path, None


def heuristic_argv_and_stdin(case):
    long = "A" * 512
    rule = str(case.get("label_rule", ""))
    source = str(case.get("source_path", ""))
    case_id = str(case.get("case_id", ""))
    if "CWE129" in case_id or "CWE129" in source:
        return ["11"], "11\n"
    wants_arg = any(token in rule for token in ("argv",)) or "argv" in source
    args = [long] if wants_arg else []
    stdin = long + "\n"
    return args, stdin


def parse_cwes(output):
    return sorted({f"CWE-{m.group(1)}" for m in CWE_RE.finditer(output)})


def filter_bo_cwes(cwes):
    return [cwe for cwe in cwes if cwe.rsplit("-", 1)[-1] in BO_CWE_IDS]


def filter_cwe_checker_cwes(cwes):
    ids = CWE_CHECKER_PAPER_IDS if parse_bool(os.environ.get("CWE_CHECKER_INCLUDE_676", False)) else CWE_CHECKER_BO_IDS
    return [cwe for cwe in cwes if cwe.rsplit("-", 1)[-1] in ids]


def parse_cwe_checker_cwes(output):
    # cwe_checker may print INFO lines containing strings such as "CWE676"
    # before the actual JSON report. Only the JSON findings should count.
    decoder = json.JSONDecoder()
    cwes = set()
    for idx, char in reversed(list(enumerate(output))):
        if char not in "[{":
            continue
        try:
            report, end = decoder.raw_decode(output[idx:])
        except json.JSONDecodeError:
            continue
        if output[idx + end :].strip():
            continue
        stack = [report]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for value in item.values():
                    if isinstance(value, str):
                        cwes.update(parse_cwes(value))
                    elif isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(item, list):
                stack.extend(item)
        return filter_cwe_checker_cwes(sorted(cwes))
    return []


def parse_sarif_cwes(path: Path):
    if not path.exists():
        return []
    try:
        sarif = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    cwes = set()
    for run in sarif.get("runs", []):
        rules = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule = rules.get(result.get("ruleId", ""), {})
            texts = [result.get("ruleId", ""), result.get("message", {}).get("text", "")]
            texts.extend(rule.get("properties", {}).get("tags", []))
            texts.append(rule.get("shortDescription", {}).get("text", ""))
            texts.append(rule.get("fullDescription", {}).get("text", ""))
            for text in texts:
                cwes.update(parse_cwes(str(text)))
    return filter_bo_cwes(sorted(cwes))


def parse_sarif_result_cwes(sarif):
    cwes = set()
    for run in sarif.get("runs", []):
        rule_list = run.get("tool", {}).get("driver", {}).get("rules", [])
        rules_by_id = {rule.get("id", ""): rule for rule in rule_list}
        for result in run.get("results", []):
            rule = result.get("rule") or {}
            rule_id = result.get("ruleId", "")
            full_rule = rules_by_id.get(rule_id, {}) if rule_id else {}
            if isinstance(result.get("ruleIndex"), int):
                index = result["ruleIndex"]
                if 0 <= index < len(rule_list):
                    full_rule = rule_list[index]
            # SARIF results often contain only a stub rule object
            # {"id": ..., "index": ...}; the CWE tags live in the full rule
            # metadata under tool.driver.rules.
            if full_rule:
                merged_rule = dict(full_rule)
                merged_rule.update(rule)
                rule = merged_rule
            texts = [
                rule_id,
                rule.get("id", ""),
                result.get("message", {}).get("text", ""),
                rule.get("shortDescription", {}).get("text", ""),
                rule.get("fullDescription", {}).get("text", ""),
            ]
            texts.extend(rule.get("properties", {}).get("tags", []))
            for text in texts:
                cwes.update(parse_cwes(str(text)))
    return filter_bo_cwes(sorted(cwes))


def parse_codeql_cwes(output):
    marker = "SARIF_JSON:"
    if marker not in output:
        return []
    sarif_text = output.rsplit(marker, 1)[-1].strip()
    try:
        sarif = json.loads(sarif_text)
    except json.JSONDecodeError:
        return []
    return parse_sarif_result_cwes(sarif)


def parse_binabsinspector_cwes(output):
    cwes = set()
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if record.get("logger") != "CWE":
            continue
        message = str(record.get("message", ""))
        # BASICS stack benchmarks score stack BO. BinAbsInspector's memory
        # engine also emits heap OOB findings as CWE119/CWE787; those are real
        # findings, but they are not positives for this stack-only benchmark.
        if re.search(r"\bHeap Out[- ]of[- ]Bound\b", message, re.IGNORECASE):
            continue
        if BAI_RE.search(message):
            cwes.update(parse_cwes(message))
    return filter_bo_cwes(sorted(cwes))


def parse_flawfinder_cwes(output):
    cwes = set()
    reader = csv.DictReader(output.splitlines())
    if reader.fieldnames and "CWEs" in reader.fieldnames:
        for row in reader:
            # FF1013 flags plain statically-sized char arrays as CWE-119/120.
            # On Juliet this fires equally in good-only and bad-only cases and
            # is not a concrete BO report for the benchmark's sink.
            if row.get("RuleId") == "FF1013" and row.get("Name") == "char":
                continue
            cwes.update(parse_cwes(row.get("CWEs", "")))
        return filter_bo_cwes(sorted(cwes))
    return filter_bo_cwes(parse_cwes(output))


def parse_arbiter_cwes(output):
    if not ARBITER_REPORTS_RE.search(output):
        return []
    cwe = os.environ.get("ARBITER_REPORTED_CWE", "CWE-121")
    return filter_bo_cwes(parse_cwes(cwe)) or ["CWE-121"]


def run_valgrind(binary, case, timeout_sec):
    args, stdin_text = heuristic_argv_and_stdin(case)
    if have_exe("valgrind"):
        cmd = ["valgrind", "--tool=memcheck", "--leak-check=no", "--error-exitcode=99", "--track-origins=no", str(binary), *args]
    elif docker_image_exists("basics-valgrind:latest"):
        mount, inner = docker_mount_for(binary)
        cmd = [
            "docker", "run", "--rm", "-i", "-v", f"{mount}:/work", "basics-valgrind:latest",
            "--tool=memcheck", "--leak-check=no", "--error-exitcode=99", "--track-origins=no", inner, *args,
        ]
    else:
        return {"status": "tool_missing", "error": "valgrind_missing", "output": "", "returncode": ""}
    rc, out, err = run_interruptible(cmd, timeout_sec, stdin_text=stdin_text)
    valgrind_found_memory_error = bool(MEMCHECK_RE.search(out)) or rc == 99
    status = "timeout" if err else ("ok" if rc == 0 or valgrind_found_memory_error else "run_error")
    return {"status": status, "error": err or (f"exit={rc}" if status == "run_error" else ""), "output": out, "returncode": rc}


def run_cwe_checker(binary, case, timeout_sec):
    del case
    partial = "CWE119,CWE676" if parse_bool(os.environ.get("CWE_CHECKER_INCLUDE_676", False)) else "CWE119"
    if have_exe("cwe_checker"):
        cmd = ["cwe_checker", "--partial", partial, "--json", str(binary)]
    elif docker_image_exists("ghcr.io/fkie-cad/cwe_checker:latest"):
        mount, inner = docker_mount_for(binary)
        cmd = [
            "docker", "run", "--rm", "-v", f"{mount}:/input:ro",
            "ghcr.io/fkie-cad/cwe_checker:latest", "--partial", partial, f"/input/{Path(inner).name}", "--json",
        ]
    else:
        return {"status": "tool_missing", "error": "cwe_checker_missing", "output": "", "returncode": ""}
    rc, out, err = run_interruptible(cmd, timeout_sec)
    status = "timeout" if err else ("ok" if rc == 0 else "run_error")
    return {"status": status, "error": err or (f"exit={rc}" if status == "run_error" else ""), "output": out, "returncode": rc}


def run_binabsinspector(binary, case, timeout_sec):
    bai_timeout = max(1, timeout_sec - 10) if timeout_sec else 300
    bai_opts = ["-json", "-timeout", str(bai_timeout)]
    # BinAbsInspector's selectable checkers do not include CWE119/CWE787.
    # Its memory-corruption engine emits those independently. CWE676 is only a
    # dangerous-function checker, so keep it opt-in for paper-compatible runs.
    if parse_bool(os.environ.get("BAI_ENABLE_CWE676", False)):
        bai_opts = ["-check", "CWE676", *bai_opts]
    bai_script_arg = "@@" + " ".join(bai_opts)
    if docker_image_exists("bai:latest"):
        mount, inner = docker_mount_for(binary)
        case_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(case.get("case_id", binary.stem)))
        workspace = ROOT / ".tool_tmp" / "bai_workspace" / f"{os.getpid()}_{case_id}"
        (workspace / "BinAbsInspector" / "~").mkdir(parents=True, exist_ok=True)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{workspace}:/data/workspace",
            "-v", f"{mount}:/input:ro",
            "bai:latest",
            bai_script_arg, "-import", f"/input/{Path(inner).name}",
        ]
    else:
        ghidra = os.environ.get("GHIDRA_HEADLESS")
        if not ghidra:
            for candidate in (
                Path.home() / "tools" / "ghidra_12.0.4_PUBLIC" / "support" / "analyzeHeadless",
                Path.home() / "tools" / "ghidra_10.1.2_PUBLIC" / "support" / "analyzeHeadless",
            ):
                if candidate.exists():
                    ghidra = str(candidate)
                    break
        if not ghidra:
            return {"status": "tool_missing", "error": "binabsinspector_missing", "output": "", "returncode": ""}
        project = ROOT / ".tool_tmp" / "bai_projects"
        project.mkdir(parents=True, exist_ok=True)
        cmd = [ghidra, str(project), f"bai_{binary.stem}", "-import", str(binary), "-postScript", "BinAbsInspector", bai_script_arg]
    rc, out, err = run_interruptible(cmd, timeout_sec)
    status = "timeout" if err else ("ok" if rc == 0 else "run_error")
    return {"status": status, "error": err or (f"exit={rc}" if status == "run_error" else ""), "output": out, "returncode": rc}


def run_rex(binary, case, timeout_sec):
    del binary, case, timeout_sec
    rex_python = os.environ.get("REX_PYTHON", str(ROOT / "tools" / "rex-venv" / "bin" / "python"))
    if not Path(rex_python).exists() and have_exe("python3"):
        rex_python = "python3"
    check = subprocess.run(
        [rex_python, "-c", "import angr, rex; print('ok')"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if check.returncode != 0:
        return {"status": "tool_missing", "error": "rex_or_angr_missing", "output": check.stdout, "returncode": check.returncode}
    return {
        "status": "unsupported",
        "error": "rex_requires_crashing_input; manifest has labels but no per-case crash input",
        "output": "REX is installed, but this harness does not synthesize crashing inputs for Juliet/SARD cases.",
        "returncode": 0,
    }


def run_manticore(binary, case, timeout_sec):
    if not docker_image_exists("trailofbits/manticore:latest"):
        return {"status": "tool_missing", "error": "manticore_missing", "output": "", "returncode": ""}
    binary, build_error = build_manticore_binary(binary, case)
    if build_error:
        return {"status": "compile_error", "error": build_error, "output": "", "returncode": ""}
    mount, inner = docker_mount_for(binary)
    workspace = ROOT / ".tool_tmp" / "manticore_workspace" / binary.stem
    shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{mount}:/input:ro",
        "-v", f"{workspace}:/workspace",
        "trailofbits/manticore:latest",
        "manticore", "--no-colors", "--workspace", "/workspace", "--core.timeout", str(timeout_sec),
        f"/input/{Path(inner).name}",
    ]
    rc, out, err = run_interruptible(cmd, timeout_sec + 10)
    testcase_errors = []
    for stderr_path in sorted(workspace.glob("test_*.stderr")):
        text = stderr_path.read_text(encoding="utf-8", errors="replace")
        if text.strip():
            testcase_errors.append(f"{stderr_path.name}:\n{text.strip()}")
    if testcase_errors:
        out += "\nMANTICORE_TESTCASE_STDERR:\n" + "\n\n".join(testcase_errors[:8])
    infra_error = next((text for text in testcase_errors if MANTICORE_INFRA_RE.search(text)), None)
    if infra_error:
        return {
            "status": "run_error",
            "error": "manticore_runtime_infra_error",
            "output": out,
            "returncode": rc,
        }
    status = "timeout" if err else ("ok" if rc == 0 else "run_error")
    return {"status": status, "error": err or (f"exit={rc}" if status == "run_error" else ""), "output": out, "returncode": rc}


def build_manticore_binary(binary, case):
    compile_cmd = case.get("compile", {}).get("command") or []
    if not compile_cmd or Path(str(compile_cmd[0])).name not in {"gcc", "cc"}:
        return binary, None

    case_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(case.get("case_id", binary.stem)))
    out_dir = ROOT / ".tool_tmp" / "manticore_bins" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    rebuilt = out_dir / binary.name
    if rebuilt.exists():
        return rebuilt, None

    docker_cmd = []
    skip_next = False
    old_roots = [
        "/home/ubuntu/BASICS",
        "/home/luisf/Work/Projects/BASICS",
        str(ROOT),
    ]
    for index, part in enumerate(compile_cmd):
        if skip_next:
            skip_next = False
            continue
        text = str(part)
        if text == "-o":
            docker_cmd.extend(["-o", f"/work/{rebuilt.relative_to(ROOT)}"])
            skip_next = True
            continue
        for old_root in old_roots:
            if text.startswith(old_root + "/"):
                text = "/work/" + text[len(old_root) + 1 :]
                break
        else:
            if text.startswith("Benchmarks/"):
                text = "/work/" + text
        docker_cmd.append(text)

    if "-o" not in [str(part) for part in compile_cmd]:
        docker_cmd.extend(["-o", f"/work/{rebuilt.relative_to(ROOT)}"])

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{ROOT}:/work",
        "-w",
        "/work",
        "trailofbits/manticore:latest",
        *docker_cmd,
    ]
    rc, out, err = run_interruptible(cmd, 120)
    if err:
        return binary, f"manticore_rebuild_timeout:{out[-800:]}"
    if rc != 0:
        return binary, f"manticore_rebuild_failed:{out[-800:]}"
    if not rebuilt.exists():
        return binary, "manticore_rebuild_missing_output"
    return rebuilt, None


def run_flawfinder(binary, case, timeout_sec):
    del binary
    source, err = source_path_for(case)
    if err:
        return {"status": "source_error", "error": err, "output": "", "returncode": ""}
    venv_flawfinder = ROOT / "tools" / "source-venv" / "bin" / "flawfinder"
    if have_exe("flawfinder"):
        exe = "flawfinder"
    elif venv_flawfinder.exists():
        exe = str(venv_flawfinder)
    else:
        return {"status": "tool_missing", "error": "flawfinder_missing", "output": "", "returncode": ""}
    cmd = [exe, "--quiet", "--dataonly", "--csv", str(source)]
    rc, out, timeout = run_interruptible(cmd, timeout_sec)
    # flawfinder returns nonzero for some scan/report conditions; if it produced
    # parseable output, keep the row usable.
    has_output = bool(out.strip())
    status = "timeout" if timeout else ("ok" if rc == 0 or has_output else "run_error")
    return {"status": status, "error": timeout or (f"exit={rc}" if status == "run_error" else ""), "output": out, "returncode": rc}


def run_codeql(binary, case, timeout_sec):
    del binary
    source, err = source_path_for(case)
    if err:
        return {"status": "source_error", "error": err, "output": "", "returncode": ""}
    codeql = os.environ.get("CODEQL_BIN")
    bundled = ROOT / "tools" / "codeql" / "codeql"
    if not codeql and bundled.exists():
        codeql = str(bundled)
    if not codeql and have_exe("codeql"):
        codeql = "codeql"
    if not codeql:
        return {"status": "tool_missing", "error": "codeql_missing", "output": "", "returncode": ""}

    case_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", case["case_id"])
    work = ROOT / ".tool_tmp" / "codeql" / case_id
    db = work / "db"
    sarif = work / "results.sarif"
    if db.exists():
        subprocess.run(["rm", "-rf", str(db)], check=False)
    work.mkdir(parents=True, exist_ok=True)

    compile_cmd = case.get("compile", {}).get("command")
    if compile_cmd:
        normalized = []
        old_roots = [
            "/home/ubuntu/BASICS",
            "/home/luisf/Work/Projects/BASICS",
            str(Path(__file__).resolve().parents[1]),
        ]
        for part in compile_cmd:
            text = str(part)
            for old_root in old_roots:
                if text.startswith(old_root + "/"):
                    text = str(ROOT / text[len(old_root) + 1:])
                    break
            else:
                candidate = ROOT / text
                if text.startswith("Benchmarks/") or candidate.exists():
                    text = str(candidate)
            normalized.append(text)
        build_cmd = " ".join(shlex.quote(part) for part in normalized)
    else:
        # SARD-style single-source fallback.
        out = work / "a.out"
        build_cmd = " ".join(
            shlex.quote(str(part))
            for part in [
                "gcc", "-std=gnu99", "-g", "-O0", "-fno-stack-protector", "-no-pie",
                "-Wno-implicit-function-declaration", str(source.relative_to(ROOT)), "-o", str(out.relative_to(ROOT)),
            ]
        )

    codeql_threads = os.environ.get("CODEQL_THREADS", "1")
    codeql_ram = os.environ.get("CODEQL_RAM_MB", "4096")

    create_cmd = [
        codeql, "database", "create", str(db),
        "--language=cpp",
        "--source-root", str(source.parent),
        "--command", build_cmd,
        "--threads", codeql_threads,
        "--overwrite",
    ]
    query_specs = [CODEQL_DEFAULT_QUERY]
    query_specs.extend(str(path) for path in CODEQL_EXTRA_QUERIES if path.exists())
    analyze_cmd = [
        codeql, "database", "analyze", str(db),
        *query_specs,
        "--threads", codeql_threads,
        "--ram", codeql_ram,
        "--format=sarif-latest",
        "--output", str(sarif),
    ]
    rc1, out1, err1 = run_interruptible(create_cmd, timeout_sec)
    if err1 or rc1 != 0:
        status = "timeout" if err1 else "run_error"
        return {"status": status, "error": err1 or f"database_create_exit={rc1}", "output": out1, "returncode": rc1}
    rc2, out2, err2 = run_interruptible(analyze_cmd, timeout_sec)
    output = out1 + "\n" + out2
    if sarif.exists():
        output += "\nSARIF_JSON:\n" + sarif.read_text(encoding="utf-8", errors="replace")
    status = "timeout" if err2 else ("ok" if rc2 == 0 else "run_error")
    return {"status": status, "error": err2 or (f"database_analyze_exit={rc2}" if status == "run_error" else ""), "output": output, "returncode": rc2}


def run_arbiter(binary, case, timeout_sec):
    template = os.environ.get("ARBITER_TEMPLATE")
    if not template:
        return {
            "status": "unsupported",
            "error": "arbiter_requires_ARBITER_TEMPLATE; use a BO-specific VD template, not Arbiter's built-in non-BO templates",
            "output": "Arbiter is template-driven. Set ARBITER_TEMPLATE to a BO-specific vulnerability description before running it.",
            "returncode": 0,
        }
    template_path = Path(template).expanduser()
    if not template_path.is_absolute():
        template_path = ROOT / template_path
    if not template_path.exists():
        return {"status": "tool_missing", "error": f"arbiter_template_missing:{template_path}", "output": "", "returncode": ""}

    arbiter_root = Path(os.environ.get("ARBITER_ROOT", ROOT / "tools" / "arbiter")).expanduser()
    runner = Path(os.environ.get("ARBITER_RUNNER", arbiter_root / "vuln_templates" / "run_arbiter.py")).expanduser()
    arbiter_python = Path(os.environ.get("ARBITER_PYTHON", ROOT / "tools" / "arbiter-venv" / "bin" / "python")).expanduser()
    if not runner.exists():
        return {"status": "tool_missing", "error": f"arbiter_runner_missing:{runner}", "output": "", "returncode": ""}
    if not arbiter_python.exists() and have_exe("python3"):
        arbiter_python = Path("python3")

    case_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", case["case_id"])
    work = ROOT / ".tool_tmp" / "arbiter" / case_id
    log_dir = work / "logs"
    json_dir = work / "json"
    work.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    for stale in work.glob("ArbiterReport_*"):
        stale.unlink()

    cmd = [
        str(arbiter_python),
        str(runner),
        "-f",
        str(template_path),
        "-t",
        str(binary),
        "-l",
        str(log_dir),
        "-j",
        str(json_dir),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{arbiter_root}:{env.get('PYTHONPATH', '')}" if arbiter_root.exists() else env.get("PYTHONPATH", "")
    env.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
    rc, out, err = run_interruptible(cmd, timeout_sec, cwd=work, env=env)
    reports = sorted(work.glob("ArbiterReport_*"))
    output = out + f"\nARBITER_REPORTS: {len(reports)}\n"
    if reports:
        output += "\n".join(str(path.relative_to(ROOT)) for path in reports)
    status = "timeout" if err else ("ok" if rc == 0 else "run_error")
    return {"status": status, "error": err or (f"exit={rc}" if status == "run_error" else ""), "output": output, "returncode": rc}


RUNNERS = {
    "arbiter": run_arbiter,
    "valgrind": run_valgrind,
    "cwe_checker": run_cwe_checker,
    "binabsinspector": run_binabsinspector,
    "rex": run_rex,
    "manticore": run_manticore,
    "flawfinder": run_flawfinder,
    "codeql": run_codeql,
}


def classify(tool, result):
    output = result["output"]
    if tool == "cwe_checker":
        cwes = parse_cwe_checker_cwes(output)
    elif tool == "binabsinspector":
        cwes = parse_binabsinspector_cwes(output)
    elif tool == "flawfinder":
        cwes = parse_flawfinder_cwes(output)
    elif tool == "codeql":
        cwes = parse_codeql_cwes(output)
    elif tool == "arbiter":
        cwes = parse_arbiter_cwes(output)
    else:
        cwes = filter_bo_cwes(parse_cwes(output))
    if result["status"] != "ok":
        return False, cwes
    if tool == "valgrind":
        return bool(MEMCHECK_RE.search(output)) or result.get("returncode") == 99, cwes
    if tool == "binabsinspector":
        return bool(cwes), cwes
    if tool == "cwe_checker":
        return bool(cwes), cwes
    if tool == "manticore":
        return bool(MANTICORE_RE.search(output)), cwes
    if tool == "flawfinder":
        return bool(cwes), cwes
    if tool == "codeql":
        return bool(cwes), cwes
    if tool == "arbiter":
        return bool(ARBITER_REPORTS_RE.search(output)), cwes
    return False, cwes


def empty_row(case, tool):
    return {
        "case_id": case["case_id"],
        "dataset": case.get("dataset", ""),
        "tool": tool,
        "true_present_vuln": case.get("true_present_vuln", ""),
        "label_confidence": case.get("label_confidence", ""),
        "label_rule": case.get("label_rule", ""),
        "entry_function": case.get("entry_function", ""),
        "source_path": case.get("source_path", ""),
        "binary_path": case.get("binary_path", ""),
        "status": "ok",
        "error": "",
        "elapsed_sec": 0.0,
        "analysis_exec_time_sec": "",
        "reported_vuln": False,
        "reported_cwes": "",
        "report_violation_count": 0,
        "patched": False,
        "patch_manifest_entries": 0,
        "patch_validated": False,
        "patch_validation_status": "not_applicable",
        "stdout_log_path": "",
        "report_path": "",
        "manifest_path": "",
        "returncode": "",
    }


def run_case(tool, case, logs_dir, timeout_sec, compile_missing=False):
    row = empty_row(case, tool)
    binary, err = ensure_binary(case, compile_missing=compile_missing)
    if err:
        row["status"] = "compile_error" if err.startswith("compile_") else "binary_error"
        row["error"] = err
        return row
    log_path = logs_dir / f"{case['case_id']}.log"
    start = time.perf_counter()
    result = RUNNERS[tool](binary, case, timeout_sec)
    elapsed = time.perf_counter() - start
    log_path.write_text(result["output"], encoding="utf-8", errors="replace")
    reported, cwes = classify(tool, result)
    row.update(
        {
            "status": result["status"],
            "error": result["error"],
            "elapsed_sec": round(elapsed, 4),
            "analysis_exec_time_sec": round(elapsed, 4),
            "reported_vuln": reported,
            "reported_cwes": ";".join(cwes),
            "report_violation_count": len(cwes) if reported else 0,
            "stdout_log_path": str(log_path.relative_to(ROOT)),
            "returncode": result["returncode"],
        }
    )
    return row


def print_progress(message):
    with PRINT_LOCK:
        print(message, flush=True)


def run_case_job(tool, idx, total, case, logs_dir, timeout_sec, compile_missing):
    if STOP_EVENT.is_set():
        row = empty_row(case, tool)
        row["status"] = "interrupted"
        row["error"] = "skipped_after_interrupt"
        return tool, idx, row
    row = run_case(tool, case, logs_dir, timeout_sec, compile_missing=compile_missing)
    print_progress(
        f"[{tool} {idx}/{total}] {case['case_id']}: "
        f"{row['status']} reported={row['reported_vuln']} cwes={row['reported_cwes']}"
    )
    return tool, idx, row


def write_results(out_dir, rows):
    fieldnames = list(empty_row({"case_id": ""}, "tool").keys())
    csv_path = out_dir / "results.csv"
    json_path = out_dir / "results.json"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return csv_path, json_path


def print_tool_status():
    statuses = {
        "valgrind": have_exe("valgrind") or docker_image_exists("basics-valgrind:latest"),
        "cwe_checker": have_exe("cwe_checker") or docker_image_exists("ghcr.io/fkie-cad/cwe_checker:latest"),
        "binabsinspector": docker_image_exists("bai:latest") or bool(os.environ.get("GHIDRA_HEADLESS")),
        "rex": subprocess.run([os.environ.get("REX_PYTHON", str(ROOT / "tools" / "rex-venv" / "bin" / "python")), "-c", "import angr, rex"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if Path(os.environ.get("REX_PYTHON", str(ROOT / "tools" / "rex-venv" / "bin" / "python"))).exists()
        else False,
        "manticore": docker_image_exists("trailofbits/manticore:latest"),
        "flawfinder": have_exe("flawfinder") or (ROOT / "tools" / "source-venv" / "bin" / "flawfinder").exists(),
        "codeql": have_exe("codeql") or (ROOT / "tools" / "codeql" / "codeql").exists(),
        "arbiter": (
            Path(os.environ.get("ARBITER_RUNNER", ROOT / "tools" / "arbiter" / "vuln_templates" / "run_arbiter.py")).exists()
            and bool(os.environ.get("ARBITER_TEMPLATE"))
        ),
    }
    for name in RUNNERS:
        print(f"{name}: {'available' if statuses.get(name) else 'missing'}")


def main():
    parser = argparse.ArgumentParser(description="Run external vulnerability tools over the BASICS stack benchmark manifest.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--tool", choices=sorted(RUNNERS), action="append", default=[])
    parser.add_argument("--dataset", action="append", default=[])
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--include-label-rule", action="append", default=[])
    parser.add_argument("--exclude-label-rule", action="append", default=[])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--timeout-sec", type=int, default=300)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Parallel case workers across the selected tool/case matrix. Use 1 for sequential execution.",
    )
    parser.add_argument(
        "--compile-missing",
        action="store_true",
        help="Compile missing binaries on demand. Standard benchmark flow leaves this off and runs scripts/prepare_external_benchmarks.py first.",
    )
    parser.add_argument("--list-tools", action="store_true")
    args = parser.parse_args()

    if args.list_tools:
        print_tool_status()
        return

    tools = args.tool or ["valgrind", "cwe_checker", "binabsinspector", "rex", "manticore", "flawfinder", "codeql"]
    cases = load_cases(args.manifest)
    if args.dataset:
        allow = set(args.dataset)
        cases = [c for c in cases if c.get("dataset") in allow]
    if args.case_id:
        needles = [n.lower() for n in args.case_id]
        cases = [c for c in cases if any(n in c["case_id"].lower() for n in needles)]
    if args.include_label_rule:
        allow = set(args.include_label_rule)
        cases = [c for c in cases if c.get("label_rule") in allow]
    if args.exclude_label_rule:
        skip = set(args.exclude_label_rule)
        cases = [c for c in cases if c.get("label_rule") not in skip]
    if args.limit is not None:
        cases = cases[: args.limit]
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    rows_by_tool = {tool: [] for tool in tools}
    out_dirs = {}
    logs_dirs = {}
    for tool in tools:
        out_dir = RESULTS_DIR / tool / timestamp
        logs_dir = out_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        out_dirs[tool] = out_dir
        logs_dirs[tool] = logs_dir

    jobs = [
        (tool, idx, case)
        for tool in tools
        for idx, case in enumerate(cases, start=1)
    ]
    if not jobs:
        print_progress("No matching cases selected; writing empty result files.")
    elif args.workers == 1:
        for tool, idx, case in jobs:
            _, _, row = run_case_job(
                tool, idx, len(cases), case, logs_dirs[tool], args.timeout_sec, args.compile_missing
            )
            rows_by_tool[tool].append((idx, row))
    else:
        print_progress(
            f"Running {len(jobs)} tool/case job(s) with {min(args.workers, len(jobs))} worker(s)."
        )
        executor = ThreadPoolExecutor(max_workers=min(args.workers, len(jobs)))
        futures = {
            executor.submit(
                run_case_job,
                tool,
                idx,
                len(cases),
                case,
                logs_dirs[tool],
                args.timeout_sec,
                args.compile_missing,
            )
            for tool, idx, case in jobs
        }
        try:
            while futures:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    tool, idx, row = future.result()
                    rows_by_tool[tool].append((idx, row))
        except KeyboardInterrupt:
            STOP_EVENT.set()
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)

    for tool in tools:
        rows = [row for _, row in sorted(rows_by_tool[tool], key=lambda item: item[0])]
        csv_path, json_path = write_results(out_dirs[tool], rows)
        print(f"Wrote {tool} results:\n  CSV: {csv_path}\n  JSON: {json_path}")


if __name__ == "__main__":
    main()
