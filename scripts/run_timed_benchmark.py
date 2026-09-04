#!/usr/bin/env python3
"""Resumable BASICS stage-timing runner; canonical output is append-only JSONL."""
import argparse, json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _as_text(value):
    """Normalize subprocess output, including bytes from TimeoutExpired."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--timeout-sec", type=int, default=180)
    ap.add_argument("--no-patching", action="store_true")
    ap.add_argument("--jobs", type=int, default=1, help="Reserved for the documented run configuration; execution is serial.")
    args = ap.parse_args()
    args.manifest = args.manifest.resolve()
    args.output = args.output.resolve()
    obj = json.loads(args.manifest.read_text())
    cases = obj if isinstance(obj, list) else obj.get("cases", [])
    if args.limit is not None: cases = cases[:args.limit]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if args.output.exists():
        for line in args.output.read_text().splitlines():
            try:
                r=json.loads(line)
                if r.get("execution_status") in {"completed","timeout","error","compile_error"}: done.add(r["case_id"])
            except json.JSONDecodeError: pass
    logdir=args.output.parent / "logs"; logdir.mkdir(exist_ok=True)
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    config_id=f"cfg-fast-static-steps10000-active64-recursion1-timeout{args.timeout_sec}-jobs{args.jobs}"
    with args.output.open("a", encoding="utf-8") as out:
        for i, case in enumerate(cases,1):
            if case["case_id"] in done: continue
            binary=ROOT / case["binary_path"]
            if not binary.exists():
                binary.parent.mkdir(parents=True, exist_ok=True)
                cc=case.get("compile",{}).get("command",[])
                cp=subprocess.run(cc,cwd=ROOT,capture_output=True,text=True) if cc else None
                if not binary.exists():
                    err="binary_missing" if cp is None else f"compile_exit={cp.returncode}: {(cp.stdout+cp.stderr)[-500:]}"
                    rec={"dataset":case.get("dataset"),"case_id":case["case_id"],"source_path":case.get("source_path"),"binary_path":case.get("binary_path"),"entry_function":case.get("entry_function") or case.get("analysis_entry"),"ground_truth":case.get("true_present_vuln"),"execution_status":"compile_error","error":err,"timestamp":datetime.now(timezone.utc).isoformat(),"basics_git_commit":commit,"configuration_id":config_id,"run_id":args.output.parent.name}
                    out.write(json.dumps(rec)+"\n"); out.flush(); continue
            cmd=[str(ROOT/"run_basics.sh"),"--no-recompilation-ltl","--cfg-mode","fast","--function-simulation","static","--patched-function-simulation","static","--concolic-step-limit","10000"]
            if args.no_patching: cmd.append("--no-patching")
            if case.get("entry_function") or case.get("analysis_entry"):
                cmd += ["--analysis-entry",str(case.get("entry_function") or case.get("analysis_entry"))]
            cmd += [str(binary)]
            start=time.perf_counter(); status="completed"; error=None; timing=None
            try:
                p=subprocess.run(cmd,cwd=ROOT,env={**os.environ,"PYTHON_BIN":"/home/ubuntu/.local/python311/bin/python3.11"},capture_output=True,text=True,timeout=args.timeout_sec)
                text=_as_text(p.stdout)+_as_text(p.stderr)
                markers=[x[len("@@BASICS_TIMING "):] for x in text.splitlines() if x.startswith("@@BASICS_TIMING ")]
                timing=json.loads(markers[-1]) if markers else None
                if p.returncode != 0: status="error"; error=f"exit={p.returncode}"
            except subprocess.TimeoutExpired as e:
                text=_as_text(e.stdout)+_as_text(e.stderr); status="timeout"; error=f"timeout={args.timeout_sec}s"
            except Exception as e: text=""; status="error"; error=repr(e)
            elapsed=time.perf_counter()-start
            log=logdir/(case["case_id"]+".log"); log.write_text(text,encoding="utf-8")
            rec={"dataset":case.get("dataset"),"case_id":case["case_id"],"source_path":case.get("source_path"),"binary_path":case.get("binary_path"),"entry_function":case.get("entry_function") or case.get("analysis_entry"),"ground_truth":case.get("true_present_vuln"),"classification":None,"detected_properties":[],"assigned_cwes":[],"execution_status":status,"error":error,"end_to_end_seconds":elapsed,"patch_attempted":False,"patch_succeeded":False,"patch_validation_result":None,"stdout_log_path":str(log.relative_to(ROOT)),"basics_git_commit":commit,"configuration_id":config_id,"run_id":args.output.parent.name,"timestamp":datetime.now(timezone.utc).isoformat()}
            if timing: rec.update(timing); rec["end_to_end_seconds"]=timing.get("end_to_end_seconds",elapsed)
            out.write(json.dumps(rec,sort_keys=True)+"\n"); out.flush(); print(f"[{i}/{len(cases)}] {case['case_id']} {status}",flush=True)

if __name__ == "__main__": main()
