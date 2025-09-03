# Educational Brute Force Password Cracker Demo

**WARNING:** This tool is for **EDUCATIONAL PURPOSES ONLY**. Unauthorized use or modification for malicious purposes is strictly prohibited and illegal. Use only on files you own or have explicit permission to test.

---

## Overview

This Python script demonstrates a brute force attack on password-protected ZIP and PDF files using an alphanumeric, case-sensitive character set. It is designed for educational use to understand the challenges and limitations of brute forcing passwords.

---

## Features

- Supports password-protected ZIP and PDF files.
- Configurable maximum password length (default: 7).
- Uses alphanumeric characters (a-z, A-Z, 0-9).
- Shows progress every 1000 attempts.
- Includes a delay between attempts for demonstration visibility.
- Extracts ZIP files to a folder named `extracted_files`.
- Opens extracted files or PDFs automatically on macOS.

---

## Requirements

- Python 3.6+
- `pypdf2` library for PDF support (install via `pip install pypdf2`).
- macOS (for automatic opening of files/folders using `open` command).

---

## Usage

```bash
python brute_force_demo.py --file path/to/protected_file.zip