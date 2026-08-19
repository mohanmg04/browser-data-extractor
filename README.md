# browser-data-extractor

Browser data extraction and forensic analysis for authorized security research and laboratory environments.

---

## Overview

`chrome_xtract.py` is a Python-based forensic extractor for Chromium-based browsers on Windows. It extracts stored credentials, cookies, browsing history, bookmarks, saved cards, and download records from browser profiles — supporting both legacy DPAPI (v10) and App-Bound Encryption (v20 / ABE) introduced in Chrome 127+.

> **For authorized penetration testing, red team operations, and security research only.**  
> Do not use on systems you do not own or have explicit written permission to test.

---

## Supported Browsers

| Key        | Browser                  |
|------------|--------------------------|
| `chrome`   | Google Chrome            |
| `edge`     | Microsoft Edge           |
| `brave`    | Brave Browser            |
| `chromium` | Chromium                 |
| `cft`      | Chrome for Testing       |

---

## Extracted Data Types

| Type        | Source DB / File  | Description                              |
|-------------|-------------------|------------------------------------------|
| `passwords` | `Login Data`      | Saved usernames and decrypted passwords  |
| `cookies`   | `Network/Cookies` | Session, auth, and tracking cookies      |
| `history`   | `History`         | Last 2000 visited URLs with timestamps   |
| `downloads` | `History`         | Download records with source URLs        |
| `bookmarks` | `Bookmarks`       | All bookmarks with folder paths          |
| `cards`     | `Web Data`        | Saved credit/debit card numbers          |
| `all`       | All of above      | Everything in one run                    |

---

## Encryption Support

| Version | Method                          | Privilege Needed |
|---------|---------------------------------|------------------|
| v10     | DPAPI (current-user scope)      | Normal user      |
| v20     | App-Bound Encryption (ABE)      | Administrator / SYSTEM |

Chrome 127+ uses v20 (App-Bound Encryption) by default. `chrome_xtract.py` handles the full two-round DPAPI + NCrypt + AES-GCM decryption chain required for v20 blobs.

---

## Requirements

- **OS**: Windows 10 / 11
- **Python**: 3.10+
- **Privilege**: User-level for v10; **Administrator** for v20 (ABE)

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

| Argument      | Required | Description                                                   |
|---------------|----------|---------------------------------------------------------------|
| `-Browser`    | Yes      | `chrome` / `edge` / `brave` / `chromium` / `cft`             |
| `-Type`       | No       | Comma-separated types to extract (default: `all`)             |
| `-Output`     | No       | Save output to file (`.json` / `.csv` / `.txt`)               |
| `-Verbose`    | No       | Enable verbose / debug output                                 |
| `-HideBanner` | No       | Suppress the ASCII banner                                     |

### Examples

```bash
# Extract everything from Chrome
python chrome_xtract.py -Browser chrome

# Passwords and cookies from Edge only
python chrome_xtract.py -Browser edge -Type passwords,cookies

# Full forensic dump from Brave — save as JSON
python chrome_xtract.py -Browser brave -Type all -Output report.json

# History and bookmarks — save as CSV
python chrome_xtract.py -Browser chrome -Type history,bookmarks -Output out.csv

# Verbose run, suppress banner
python chrome_xtract.py -Browser chromium -Type all -Verbose -HideBanner
```

---

## Output Formats

| Format  | Extension | Notes                                       |
|---------|-----------|---------------------------------------------|
| JSON    | `.json`   | Structured by type; best for further parsing|
| CSV     | `.csv`    | Flat; all types in one sheet                |
| Text    | `.txt`    | Human-readable; sectioned by type           |
| Console | —         | Formatted tables printed to stdout          |

---

## Multi-Profile Support

The tool automatically scans all browser profiles (Default, Profile 1, Profile 2, …) found under the browser's User Data directory and aggregates results across them.

---

## Technical Notes

- Browser SQLite databases are locked while Chrome is running. `chrome_xtract.py` copies each DB to a temp location before querying, then deletes the copy.
- v20 decryption requires impersonating `NT AUTHORITY\SYSTEM` via `winlogon.exe` token duplication and NCrypt key access. This requires the tool to run as Administrator.
- Chrome timestamps are stored as microseconds since the Windows/WebKit epoch (1601-01-01). The tool converts these to human-readable UTC strings.

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
