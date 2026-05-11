#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "Benchmarks"
STACK_DATASET_DIR = BENCHMARKS / "stack_benchmark"
SARD_SOURCE_DIR = STACK_DATASET_DIR / "sard_sources"
GENERATED_BIN_DIR = STACK_DATASET_DIR / "generated_bins"

STACK_C_DIRS = [
    "CWE121_Stack_Based_Buffer_Overflow",
    "CWE124_Buffer_Underwrite",
]

SEP = re.compile(r"^-{8,}\s*$", re.MULTILINE)
BAD_RE = re.compile(r"(?:\bbad\b|_bad(?:\.|$))", re.IGNORECASE)
GOOD_RE = re.compile(r"(?:\bgood(?:g2b|b2g)?\b|_good(?:g2b|b2g)?(?:\.|$))", re.IGNORECASE)

# Manual ground-truth labels for SARD dataset.txt cases (1-indexed by separator).
# true_present_vuln reflects whether a *stack* vulnerability is present; programs with
# only heap/null-pointer/global-buffer issues are labelled False (no stack vuln).
# Each entry: (true_present_vuln, label_rule, label_confidence).
# label_rule values:
#   bounded_array_access   – properly guarded array index, no overflow
#   gets_usage             – gets() is unconditionally unsafe
#   scanf_unbounded        – fscanf/scanf with %s and no width specifier
#   scanf_width_ge_buffer  – width specifier >= buffer size (overflow or off-by-one)
#   scanf_width_lt_buffer  – width specifier < buffer size (safe)
#   integer_scan_only      – scanf/fscanf reads only integers, no char buffer at risk
#   sscanf_overflow        – sscanf with source string wider than destination buffer
#   sscanf_safe            – sscanf with source provably fits destination
#   sprintf_overflow       – sprintf/sprintf variant writes past destination buffer
#   sprintf_safe           – sprintf/sprintf variant provably fits destination
#   strcpy_overflow        – strcpy where source can exceed destination
#   strcpy_safe            – strcpy where source provably fits destination
#   stack_underwrite       – pointer offset before buffer start before write (CWE-124)
#   vsprintf_overflow      – vsprintf where formatted output exceeds destination
#   vsprintf_safe          – vsprintf where formatted output provably fits destination
#   heap_issue_only        – vulnerability (if any) is in heap memory; no stack vuln
#   vsprintf_global_safe   – vsprintf writes to a global buffer, provably fits; no stack
SARD_MANUAL_LABELS: dict[int, tuple[bool, str, str]] = {
    # --- fscanf cases ---
    1:   (False, "bounded_array_access",  "high"),    # int buffer[10], guarded index
    3:   (False, "scanf_width_lt_buffer", "high"),    # dataBuffer[100], %99s
    4:   (False, "scanf_width_lt_buffer", "high"),    # same with return-value check
    5:   (True,  "scanf_unbounded",       "high"),    # dataBuffer[100], %s
    6:   (True,  "scanf_width_ge_buffer", "high"),    # dataBuffer[100], %120s
    7:   (True,  "scanf_width_ge_buffer", "high"),    # dataBuffer[100], %100s (off-by-one)
    8:   (False, "scanf_width_lt_buffer", "high"),    # dataBuffer[100], %50s
    9:   (True,  "scanf_unbounded",       "high"),    # str1/2/3[10], %s %s %s
    # --- gets() cases ---
    10:  (True,  "gets_usage",            "high"),    # buf[10], gets()
    11:  (True,  "gets_usage",            "high"),    # buf[10], gets(), extra local vars
    # --- scanf + strcpy combinations ---
    12:  (True,  "scanf_unbounded",       "high"),    # str1/2[10], scanf %s then strcpy
    13:  (True,  "scanf_width_ge_buffer", "high"),    # str2[11] %11s → 12 bytes; strcpy to str1[10]
    14:  (True,  "strcpy_overflow",       "medium"),  # str2[11] %10s fills; strcpy off-by-one to str1[10]
    15:  (True,  "scanf_width_ge_buffer", "high"),    # str2[10], %11s → 12 bytes
    16:  (False, "scanf_width_lt_buffer", "high"),    # str1/2[10], %9s + strcpy
    17:  (False, "scanf_width_lt_buffer", "high"),    # str1/2[10], %8s + strcpy
    # --- scanf-only (no strcpy) ---
    18:  (False, "scanf_width_lt_buffer", "high"),    # address[100], %99s
    19:  (False, "scanf_width_lt_buffer", "high"),    # same, different declaration order
    20:  (False, "scanf_width_lt_buffer", "high"),    # same, slightly different layout
    21:  (False, "scanf_width_lt_buffer", "high"),    # address[100], %98s
    22:  (False, "scanf_width_lt_buffer", "high"),    # address[20], %18s
    23:  (True,  "scanf_width_ge_buffer", "high"),    # address[100], %101s → 102 bytes
    24:  (True,  "scanf_width_ge_buffer", "high"),    # address[100], %100s (off-by-one)
    25:  (True,  "scanf_unbounded",       "high"),    # address[100], %s
    26:  (False, "integer_scan_only",     "high"),    # int debug, scanf %d
    27:  (False, "integer_scan_only",     "high"),    # same, different declaration order
    28:  (False, "scanf_width_lt_buffer", "high"),    # address[20], %19s
    # --- sprintf ---
    29:  (True,  "sprintf_overflow",      "high"),    # psz_remote[100], uninitialized sources
    33:  (False, "sprintf_safe",          "high"),    # text[80], fixed short format
    34:  (True,  "sprintf_overflow",      "high"),    # psz_remote[100], uninitialized + strchr
    35:  (True,  "sprintf_overflow",      "high"),    # stack_buf[10], 18-char literal
    36:  (True,  "sprintf_overflow",      "high"),    # stack_buf[10], env-var-derived string
    37:  (True,  "sprintf_overflow",      "high"),    # buf[20], "<%s>" with argv[1], no check
    38:  (True,  "sprintf_overflow",      "high"),    # buf[20], only called when strlen > 20
    39:  (True,  "sprintf_overflow",      "medium"),  # buf[20], called when strlen < 20, <%s> adds +3
    40:  (True,  "sprintf_overflow",      "medium"),  # buf[20], called when strlen <= 20, max 23 bytes
    41:  (False, "sprintf_safe",          "high"),    # buf[20], "<%.5s>" → max 8 bytes
    42:  (True,  "sprintf_overflow",      "medium"),  # buf[20], called when strlen <= MAXSIZE(20)
    43:  (False, "sprintf_safe",          "high"),    # buf[128], 22-char literal
    44:  (True,  "sprintf_overflow",      "high"),    # buf[30], "<%.32s>" → max 35 bytes
    45:  (True,  "sprintf_overflow",      "high"),    # buf[30], "<%.29s>" → max 32 bytes
    46:  (True,  "sprintf_overflow",      "high"),    # buf[30], called when strlen >= 27
    47:  (False, "sprintf_safe",          "high"),    # buf[30], called when strlen < 27 → max 29 bytes
    48:  (True,  "sprintf_overflow",      "high"),    # buf[30], "<%s>" with argv[1], no check
    49:  (False, "sprintf_safe",          "high"),    # buf[30], "<%.27s>" → max 30 bytes, exactly fits
    # --- sscanf ---
    50:  (False, "sscanf_safe",           "high"),    # dataBuffer[100], sscanf %99s fixed source
    51:  (False, "sscanf_safe",           "high"),    # dataBuffer[10], sscanf %s with 6-char source
    52:  (True,  "sscanf_overflow",       "high"),    # dataBuffer[10], sscanf %s with 18-char source
    # --- strcpy: fixed literal source ---
    53:  (False, "strcpy_safe",           "high"),    # dataBuffer[100], strcpy 15-char literal
    57:  (False, "strcpy_safe",           "high"),    # dataBuffer[100], strcpy 15-char literal (dup)
    58:  (True,  "strcpy_overflow",       "high"),    # dest[10], strcpy from heap data[49]='\0' (~50 bytes)
    65:  (True,  "strcpy_overflow",       "high"),    # buf[40], off-by-one: check is l>40, l==40 passes
    66:  (True,  "strcpy_overflow",       "high"),    # buf1/2[40], read() no null-term then strcpy
    77:  (False, "strcpy_safe",           "high"),    # stack_buf[64], strcpy 14-char literal
    78:  (False, "strcpy_safe",           "high"),    # exp_dn2[200], strcpy 15-char literal
    80:  (False, "strcpy_safe",           "high"),    # stack_buf[64], strcpy 39-char literal
    81:  (True,  "strcpy_overflow",       "high"),    # buf[30], strcpy(buf, argv[1]) no check
    82:  (True,  "strcpy_overflow",       "high"),    # buf1[5], strcpy 17-char literal
    87:  (False, "strcpy_safe",           "high"),    # canary[10], strcpy "GOOD"
    88:  (False, "strcpy_safe",           "high"),    # buf[10], strcpy "my string" (9+1=10)
    89:  (True,  "strcpy_overflow",       "high"),    # buf[10], strcpy 17-char literal
    90:  (True,  "strcpy_overflow",       "high"),    # buf[10], strcpy(buf, argv[1]) no check
    91:  (False, "strcpy_safe",           "high"),    # exp_dn[200], strcpy "lcs.mit.edu"
    92:  (False, "strcpy_safe",           "high"),    # exp_dn2[200], strcpy "sls.lcs.mit.edu"
    93:  (False, "strcpy_safe",           "high"),    # test_buf[10], strcpy "GOOD"
    94:  (True,  "strcpy_overflow",       "high"),    # buf[20], strcpy only when strlen >= MAXSIZE
    # --- heap→stack strcpy: dest is a stack buffer ---
    113: (True,  "strcpy_overflow",       "high"),    # dest[50], heap data 99 'A's
    114: (False, "strcpy_safe",           "high"),    # dest[50], heap data 49 chars
    115: (False, "strcpy_safe",           "high"),    # dest[100], heap data 99 chars
    116: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via if(1)
    117: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via else-of-if(0)
    118: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via STATIC_CONST_TRUE
    119: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via STATIC_CONST_FALSE else
    120: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via STATIC_CONST_TRUE memset(49)
    121: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via STATIC_CONST_FIVE==5
    122: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via STATIC_CONST_FIVE!=5 else
    123: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via switch(6) case 6
    124: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via switch(5) default
    125: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via while(1)
    126: (False, "strcpy_safe",           "high"),    # dest[100], heap 99 chars via while(1)
    127: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via for(i<1)
    128: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via for(h<1)
    129: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via goto
    130: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via goto
    131: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via pointer alias
    132: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via pointer alias
    133: (True,  "strcpy_overflow",       "high"),    # dest[50], heap 99 chars via double pointer
    134: (False, "strcpy_safe",           "high"),    # dest[50], heap 49 chars via double pointer
    # --- stack underwrite: negative pointer offset before buffer (CWE-124) ---
    135: (True,  "stack_underwrite",      "high"),    # dataBuffer[100], data = dataBuffer - 8
    136: (False, "strcpy_safe",           "high"),    # dataBuffer[100], data = dataBuffer (no offset)
    137: (False, "strcpy_safe",           "high"),    # same via else branch
    138: (False, "strcpy_safe",           "high"),    # same via if(5==5)
    139: (False, "strcpy_safe",           "high"),    # same via staticTrue
    140: (True,  "stack_underwrite",      "high"),    # data = dataBuffer - 8 via STATIC_CONST_FIVE==5
    141: (False, "strcpy_safe",           "high"),    # data = dataBuffer via STATIC_CONST_FIVE!=5 else
    142: (True,  "stack_underwrite",      "high"),    # data = dataBuffer - 16 via GLOBAL_CONST_TRUE
    143: (False, "strcpy_safe",           "high"),    # data = dataBuffer via GLOBAL_CONST_FALSE else
    144: (True,  "stack_underwrite",      "high"),    # data = dataBuffer - 8 via switch(6) case 6
    145: (False, "strcpy_safe",           "high"),    # data = dataBuffer via switch(6) case 6
    146: (True,  "stack_underwrite",      "high"),    # data = dataBuffer - 8 via pointer copy alias
    147: (False, "strcpy_safe",           "high"),    # data = dataBuffer via pointer copy alias
    # --- strcpy with recursion-based truncation ---
    148: (False, "strcpy_safe",           "high"),    # buf[40], shortstr() truncates to 39 chars first
    # --- vsprintf ---
    150: (False, "vsprintf_safe",         "high"),    # string[100], "Sat Sun Mon\n" = 12 chars
    152: (True,  "vsprintf_overflow",     "high"),    # string[10], "Saturday Sunday Monday\n" = 23 chars
    # --- heap-only cases: no stack vulnerability (true_present_vuln=False) ---
    # Programs below contain heap memory issues, null-pointer dereferences, or operate
    # entirely on heap/global buffers. BASICS checks stack properties, so these are
    # negative (non-vulnerable) examples that broaden the benchmark's negative class.
    # 2: excluded — fscanf(stdin,"%d",&data) then loop bound=(size_t)data; hangs when data=-1 (EOF→SIZE_MAX iterations)
    30:  (False, "heap_issue_only",       "high"),    # heap dirpath/filepath, sprintf with computed size
    31:  (False, "heap_issue_only",       "high"),    # same as 30, alternate control flow
    32:  (False, "heap_issue_only",       "high"),    # same as 30, with null-check guard
    54:  (False, "heap_issue_only",       "high"),    # malloc then buf=NULL; strcpy to null ptr
    55:  (False, "heap_issue_only",       "high"),    # malloc then data=NULL; strcpy to null ptr
    56:  (False, "heap_issue_only",       "high"),    # heap data[11], strcpy "source" (7 bytes) — safe
    59:  (False, "heap_issue_only",       "high"),    # heap str[256], safe strcpy + char assign
    60:  (False, "heap_issue_only",       "high"),    # heap dest[100] ← heap src[100] uninit
    61:  (False, "heap_issue_only",       "high"),    # heap dest[20] ← heap src[100] uninit — heap overflow
    62:  (False, "heap_issue_only",       "high"),    # heap dest[10], strcpy "123456789" (9+1) — safe
    63:  (False, "strcpy_safe",           "high"),    # stack dataBuffer[100], strcpy "fixedstringtest" (15 chars)
    64:  (False, "heap_issue_only",       "high"),    # heap[9], strcpy "shellcode" (10 bytes) — heap overflow
    67:  (False, "heap_issue_only",       "high"),    # heap buf[40], strcpy only when strlen >= 40 — heap overflow
    68:  (False, "heap_issue_only",       "high"),    # heap buf[40], strcpy only when strlen == 40 — heap off-by-one
    69:  (False, "heap_issue_only",       "high"),    # heap buf[40], strcpy only when strlen < 40 — safe
    70:  (False, "heap_issue_only",       "high"),    # heap dptr[5]=malloc(0), strcpy "STRING TEST" — heap overflow
    71:  (False, "heap_issue_only",       "high"),    # heap buf[60], strcpy when strlen < 60 — safe
    72:  (False, "heap_issue_only",       "high"),    # heap first[666], unchecked strcpy of argv[1]
    73:  (False, "heap_issue_only",       "high"),    # heap double-ptr, use-after-free pattern
    74:  (False, "heap_issue_only",       "high"),    # strcpy to null ptr before malloc — null deref
    75:  (False, "heap_issue_only",       "high"),    # heap container[256], safe strcpy "Falut!"
    76:  (False, "heap_issue_only",       "high"),    # heap buf[6], strcpy "sweven_nitwitted" (16 chars) — heap overflow
    79:  (False, "heap_issue_only",       "high"),    # heap temp1[400], safe strcpy "HEADER JUNK:"
    83:  (False, "heap_issue_only",       "high"),    # heap double-ptr, use-after-free (variant of 73)
    84:  (False, "heap_issue_only",       "high"),    # heap ptr array, strcpy to uninitialized ptr[2]
    85:  (False, "heap_issue_only",       "high"),    # heap str1[25], strcpy from uninitialized str2
    86:  (False, "heap_issue_only",       "high"),    # heap buf[25], unchecked strcpy of argv[1]
    95:  (False, "heap_issue_only",       "high"),    # heap buf[20], strcpy when strlen >= 20 — heap overflow
    96:  (False, "heap_issue_only",       "high"),    # malloc then buf=NULL; strcpy to null ptr
    97:  (False, "heap_issue_only",       "high"),    # heap data[11], strcpy "AAAAAAAAAA" (10+1) — safe
    98:  (False, "heap_issue_only",       "high"),    # heap data[10], strcpy "AAAAAAAAAA" (11) — heap overflow
    99:  (False, "heap_issue_only",       "high"),    # same as 98 via 5==5 condition
    100: (False, "heap_issue_only",       "high"),    # heap data[11], strcpy "AAAAAAAAAA" (11) — safe
    101: (False, "heap_issue_only",       "high"),    # heap data[10] via STATIC_CONST_TRUE, strcpy 11 bytes — heap overflow
    102: (False, "heap_issue_only",       "high"),    # heap data[11] via else branch, strcpy 11 bytes — safe
    103: (False, "heap_issue_only",       "high"),    # heap data[10] via for loop, strcpy 11 bytes — heap overflow
    104: (False, "heap_issue_only",       "high"),    # heap data[11] via for loop, strcpy 11 bytes — safe
    105: (False, "heap_issue_only",       "high"),    # heap data[11] via pointer alias, strcpy 11 bytes — safe
    106: (False, "heap_issue_only",       "high"),    # heap data[10] via pointer alias, strcpy 11 bytes — heap overflow
    107: (False, "heap_issue_only",       "high"),    # heap data[10] via double pointer, strcpy 11 bytes — heap overflow
    108: (False, "heap_issue_only",       "high"),    # heap data[11] via double pointer, strcpy 11 bytes — safe
    109: (False, "heap_issue_only",       "high"),    # heap dest[50] ← stack source[99 'C's] — heap overflow, no stack vuln
    110: (False, "heap_issue_only",       "high"),    # heap dest[100] ← stack source[99 'C's] — safe
    111: (False, "heap_issue_only",       "high"),    # heap dest[50] via globalTrue ← stack source[99 'C's] — heap overflow
    112: (False, "heap_issue_only",       "high"),    # heap dest[100] via globalTrue ← stack source[99 'C's] — safe
    149: (False, "vsprintf_global_safe",  "high"),    # global buffer[128], vsprintf "%d %s" → 18 chars — safe
    151: (False, "vsprintf_global_safe",  "high"),    # global buffer[80], vsprintf "%d %f %s" → small output — safe
}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def case_id_from_path(prefix: str, path: Path) -> str:
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:10]
    stem = re.sub(r"[^A-Za-z0-9_]+", "_", path.stem)
    return f"{prefix}_{stem}_{digest}"


def classify_c_filename(path: Path):
    name = path.name
    has_bad = bool(BAD_RE.search(name))
    has_good = bool(GOOD_RE.search(name))
    if has_bad and not has_good:
        return True, "filename_bad_token", "high"
    if has_good and not has_bad:
        return False, "filename_good_token", "high"
    return None, "ambiguous_filename", "low"


def compiler_for(path: Path) -> str:
    return "g++" if path.suffix == ".cpp" else "gcc"


def build_juliet_compile_command(source_path: Path) -> list[str]:
    return ["make", "-C", str(source_path.parent), "individuals"]


def prepare_c_cases(limit: int | None):
    c_root = ROOT / "Benchmarks" / "C" / "testcases"
    cases = []
    for cwe_dir in STACK_C_DIRS:
        for source in sorted((c_root / cwe_dir).rglob("*")):
            if source.suffix not in {".c", ".cpp"}:
                continue
            if source.name == "main.cpp":
                continue
            truth, rule, confidence = classify_c_filename(source)
            if truth is None:
                continue
            makefile = source.parent / "Makefile"
            if not makefile.exists():
                continue
            rel = source.relative_to(ROOT)
            case_id = case_id_from_path("juliet", rel)
            out_bin = source.with_suffix(".out")
            case = {
                "case_id": case_id,
                "dataset": "C",
                "family": "Juliet",
                "scope": "stack",
                "cwe_group": cwe_dir.split("_", 1)[0],
                "true_present_vuln": truth,
                "label_confidence": confidence,
                "label_rule": rule,
                "source_path": str(rel),
                "binary_path": str(out_bin.relative_to(ROOT)),
                "compile": {
                    "required": True,
                    "command": build_juliet_compile_command(source),
                },
            }
            cases.append(case)
            if limit is not None and len(cases) >= limit:
                return cases
    return cases


def split_sard_snippets(dataset_text: str):
    parts = [p.strip() for p in SEP.split(dataset_text)]
    return [p for p in parts if p and ("int main" in p or "#include" in p)]


def prepare_sard_cases(limit: int | None):
    sard_file = ROOT / "Benchmarks" / "SARD" / "dataset.txt"
    text = read_text(sard_file)
    snippets = split_sard_snippets(text)
    cases = []
    for idx, snippet in enumerate(snippets, start=1):
        if idx not in SARD_MANUAL_LABELS:
            continue
        truth, rule, confidence = SARD_MANUAL_LABELS[idx]
        case_id = f"sard_{idx:04d}"
        src = SARD_SOURCE_DIR / f"{case_id}.c"
        out_bin = GENERATED_BIN_DIR / "SARD" / f"{case_id}.bin"
        cases.append(
            {
                "case_id": case_id,
                "dataset": "SARD",
                "family": "SARD_snippets",
                "scope": "stack",
                "true_present_vuln": truth,
                "label_confidence": confidence,
                "label_rule": rule,
                "source_path": str(src.relative_to(ROOT)),
                "binary_path": str(out_bin.relative_to(ROOT)),
                "compile": {
                    "required": True,
                    "command": [
                        "gcc",
                        "-std=gnu99",
                        "-Wno-implicit-function-declaration",
                        "-O0",
                        "-g",
                        "-gdwarf-4",
                        "-fno-stack-protector",
                        "-fcf-protection=none",
                        "-fno-omit-frame-pointer",
                        "-march=x86-64",
                        "-mtune=generic",
                        "-no-pie",
                        str(src),
                        "-o",
                        str(out_bin),
                    ],
                },
                "snippet_source": str(sard_file.relative_to(ROOT)),
                "snippet_index": idx,
                "snippet_body": snippet,
            }
        )
        if limit is not None and len(cases) >= limit:
            break
    return cases


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def materialize_sard_sources(cases):
    SARD_SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    for case in cases:
        snippet = case.pop("snippet_body")
        if case["case_id"] == "sard_0063":
            snippet = snippet.replace(
                "    char *data = dataBuffer;\n"
                "    if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)",
                "    char *data = dataBuffer;\n"
                "    size_t dataLen = strlen(data);\n"
                "    if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)",
            )
        if case["case_id"] == "sard_0065":
            snippet = snippet.replace("            return;\n", "            return 0;\n")
        src_path = ROOT / case["source_path"]
        src_path.parent.mkdir(parents=True, exist_ok=True)
        src_path.write_text(snippet.strip() + "\n", encoding="utf-8")


def load_existing_test_bin_cases():
    tests_bin = ROOT / "tests" / "bin"
    if not tests_bin.exists():
        return []
    cases = []
    for binary in sorted(tests_bin.iterdir()):
        if not binary.is_file() or binary.name == ".gitkeep":
            continue
        name = binary.name
        if name.endswith("_patched"):
            continue
        if name.startswith("safe_"):
            truth = False
            rule = "tests_fixture_safe_prefix"
        else:
            truth = True
            rule = "tests_fixture_default_unsafe"
        cases.append(
            {
                "case_id": f"tests_{name}",
                "dataset": "tests_bin",
                "family": "BASICS_fixtures",
                "scope": "stack",
                "true_present_vuln": truth,
                "label_confidence": "high",
                "label_rule": rule,
                "binary_path": str(binary.relative_to(ROOT)),
                "compile": {"required": False, "command": []},
            }
        )
    return cases


def summarize(cases):
    pos = sum(1 for c in cases if c["true_present_vuln"])
    neg = len(cases) - pos
    return {"total": len(cases), "positive": pos, "negative": neg}


def main():
    parser = argparse.ArgumentParser(description="Prepare labeled stack-vulnerability datasets for BASICS benchmarks.")
    parser.add_argument("--c-limit", type=int, default=None, help="Limit number of C/Juliet cases (for quick iteration).")
    parser.add_argument("--sard-limit", type=int, default=None, help="Limit number of SARD snippet cases.")
    args = parser.parse_args()

    c_cases = prepare_c_cases(args.c_limit)
    sard_cases = prepare_sard_cases(args.sard_limit)
    materialize_sard_sources(sard_cases)
    tests_cases = load_existing_test_bin_cases()

    combined = {
        "meta": {
            "generated_by": "scripts/prepare_stack_datasets.py",
            "focus": "stack vulnerabilities",
        },
        "datasets": {
            "C": {"summary": summarize(c_cases), "cases": c_cases},
            "SARD": {"summary": summarize(sard_cases), "cases": sard_cases},
            "tests_bin": {"summary": summarize(tests_cases), "cases": tests_cases},
        },
    }

    write_json(STACK_DATASET_DIR / "c_stack_cases.json", c_cases)
    write_json(STACK_DATASET_DIR / "sard_stack_cases.json", sard_cases)
    write_json(STACK_DATASET_DIR / "tests_bin_stack_cases.json", tests_cases)
    write_json(STACK_DATASET_DIR / "stack_cases_combined.json", combined)

    print("Prepared datasets:")
    print(f"  C: {summarize(c_cases)}")
    print(f"  SARD: {summarize(sard_cases)}")
    print(f"  tests_bin: {summarize(tests_cases)}")
    print(f"Wrote outputs to {STACK_DATASET_DIR}")


if __name__ == "__main__":
    main()
