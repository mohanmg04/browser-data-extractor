# browser-data-extractor

Browser password extraction for authorized security research and laboratory environments.

---

## Overview

`chrome_xtract.py` is a Python-based password extractor for Windows that supports Google Chrome and Mozilla Firefox. It decrypts and extracts saved credentials from browser profiles — handling both legacy DPAPI (v10) and App-Bound Encryption (v20 / ABE) introduced in Chrome 127+.

> **For authorized penetration testing, red team operations, and security research only.**  
> Do not use on systems you do not own or have explicit written permission to test.

---

## Supported Browsers

| Key       | Browser          |
|-----------|------------------|
| `chrome`  | Google Chrome    |
| `firefox` | Mozilla Firefox  |

---

## Extracted Data

| Source              | Description                              |
|---------------------|------------------------------------------|
| Chrome `Login Data` | Saved usernames and decrypted passwords  |
| Firefox `logins.json` | Saved usernames and decrypted passwords |

---

## Encryption Support

| Browser  | Version | Method                             | Privilege Needed       |
|----------|---------|------------------------------------|------------------------|
| Chrome   | v10     | DPAPI (current-user scope)         | Normal user            |
| Chrome   | v20     | App-Bound Encryption (ABE)         | Administrator / SYSTEM |
| Firefox  | —       | NSS / PK11SDR_Decrypt via nss3.dll | Normal user            |

Chrome 127+ uses v20 (ABE) by default. The script auto-detects the version and handles the full two-round DPAPI + NCrypt + AES-GCM decryption chain automatically.

---

## Requirements

- **OS**: Windows 10 / 11
- **Python**: 3.10+
- **Privilege**: User-level for Firefox and Chrome v10; **Administrator** for Chrome v20 (ABE)
- **Firefox mode**: Mozilla Firefox must be installed (nss3.dll is loaded from the install directory)

```
pip install -r requirements.txt
```

or manually:

```
pip install cryptography
```

---

## Usage

```
python chrome_xtract.py -Browser <browser> [options]
```

### Arguments

| Argument      | Required | Description                                     |
|---------------|----------|-------------------------------------------------|
| `-Browser`    | Yes      | `chrome` or `firefox`                           |
| `-Output`     | No       | Save output to file (`.json` / `.csv` / `.txt`) |
| `-Verbose`    | No       | Enable verbose / debug output                   |
| `-HideBanner` | No       | Suppress the ASCII banner                       |

### Examples

**1. Extract passwords from Chrome**
```bash
python chrome_xtract.py -Browser chrome
```

**2. Extract passwords from Firefox**
```bash
python chrome_xtract.py -Browser firefox
```

**3. Save Chrome passwords as JSON**
```bash
python chrome_xtract.py -Browser chrome -Output passwords.json
```

**4. Save Firefox passwords as CSV**
```bash
python chrome_xtract.py -Browser firefox -Output passwords.csv
```

**5. Save as TXT**
```bash
python chrome_xtract.py -Browser chrome -Output passwords.txt
```

**6. Verbose run, suppress banner**
```bash
python chrome_xtract.py -Browser chrome -Verbose -HideBanner
```

---

## Output Formats

| Format  | Extension | Notes                                       |
|---------|-----------|---------------------------------------------|
| JSON    | `.json`   | Array of password objects; easy to parse    |
| CSV     | `.csv`    | Profile, URL, Username, Password columns    |
| Text    | `.txt`    | Human-readable, one entry per block         |
| Console | —         | Formatted table printed to stdout (default) |

---

## Multi-Profile Support

Both Chrome and Firefox profiles are automatically discovered and scanned. Results from all profiles are aggregated into a single output.

- **Chrome**: scans all directories under `User Data\` that contain a `Login Data` file
- **Firefox**: scans all directories under `%APPDATA%\Mozilla\Firefox\Profiles\` that contain a `logins.json` file

---

## Technical Notes

- Chrome's SQLite `Login Data` is locked while the browser is running. The script copies it to a temp file before querying, then deletes the copy.
- Chrome v20 decryption requires impersonating `NT AUTHORITY\SYSTEM` via `winlogon.exe` token duplication and NCrypt key access — run as Administrator.
- Firefox decryption uses `nss3.dll` loaded from the Firefox installation directory. NSS is initialized per-profile and shut down cleanly between profiles.

---

## Disclaimer

This tool is intended **exclusively** for:
- Authorized penetration testing engagements
- Red team / purple team lab exercises
- Digital forensics and incident response (DFIR) on systems with proper authorization
- Security research in controlled environments

Unauthorized use against systems you do not own or have explicit permission to test is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent laws worldwide. The author assumes no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)
