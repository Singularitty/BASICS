import os
import json

# Default flags
DEBUG = False
RECOMPILE_LTL = False

# Paths to directories
DIRECTORY = os.getcwd()
SECURITY_PROPERTIES_DIR = os.path.join(DIRECTORY, "security_properties")
LTL_MODULES_DIR = os.path.join(DIRECTORY, "src/security_property_converter")
MODEL_CHECKER_DIR = os.path.join(DIRECTORY, "src/model_checker")
REPORTS_DIR = os.path.join(DIRECTORY, "reports")
PATCHES_DIR = os.path.join(DIRECTORY, "src/vulnerability_identifier_removal/patches")

# Variables
BINARY_NAME = None

# C-lib functions database
with open(DIRECTORY + "/src/clib_functions.json", 'r', encoding='utf-8') as data:
    CLIB_FUNCTIONS = json.load(data)
    
# Vulnerability Database
with open(DIRECTORY + "/src/vulnerabilities_map.json", 'r', encoding="utf-8") as data:
    VULNERABILITY_DATABASE = json.load(data)
    
with open(DIRECTORY + "/src/vulnerabilities.json", 'r', encoding="utf-8") as data:
    VULNERABILITY_INFO = json.load(data)
    
ANGR_OPTION = None
FUNCTION_SIMULATION = "auto"
CONCOLIC_STEP_LIMIT = 10000
CONCOLIC_ACTIVE_LIMIT = 64
LTL_BACKEND = "auto"
ANALYSIS_START_ADDR = None
SCAN_MEMORY_LIMIT_MB = None  # RSS ceiling per function in scan mode; None = unlimited
MEMORY_LIMIT_MB = None  # RSS ceiling for normal whole-binary analysis; None = unlimited
INCLUDE_EXPERIMENTAL_PROPERTIES = False
    
# Functions that should not be emulated as they don't contribute to the space state
NO_EXECUTE_FUNCTIONS = [
    "fread",
    "free",
    "fclose",
    "strlen",
    "fopen",
    "strcmp",
    "malloc",
    "system",
    "exit",
    "time",
    "error",
    "perror",
    "fwrite",
    "printf", 
    "puts", 
    "putchar", 
    "putchar_unlocked", 
    "puts_unlocked", 
    "printf_unlocked", 
    "fprintf", 
    "fputs", 
    "fputc", 
    "fputc_unlocked", 
    "fputs_unlocked", 
    "fprintf_unlocked", 
    "stack_chk_fail"
]
    
STDIN_FUNCTIONS = [
    'catgets6',
    'fgets1',
    'fgets',
    'fscanf',
    'fwscanf6',
    'gets',
    'scanf',
    'read',
    'recv',
    'sscanf',
    'swscanf',
    'vfscanf',
    'vfwscanf',
    'vscanf',
    'vsscanf',
    'vswscanf',
    'vwscanf',
    'wscanf6'
]


# Hooks
GLOBAL_HOOKS = set()

# Suppress per-function verbose output during bulk scans
SCAN_MODE = False
SCAN_EXCLUDE_RUNTIME_SYMBOLS = True
SCAN_CONSTRAIN_ARG_REGS = False
SCAN_ARG_STACK_GUARD_BYTES = 0x200000
