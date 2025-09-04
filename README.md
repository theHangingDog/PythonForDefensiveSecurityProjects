# 🔍 YARA Directory Scanner

A **simple yet powerful YARA file scanner** written in Python.
It allows you to download YARA rules from remote URLs or use local ones, then recursively scan a directory for matching files.
Perfect for security researchers, malware analysts, and SOC engineers who want a quick way to identify suspicious files.

---

## ✨ Features

* 📥 **Rule Downloader** – Fetch YARA rules from URLs and save them locally.
* 🛠 **YARA Compilation** – Automatically compiles rules before scanning.
* 📂 **Recursive Scanning** – Scans entire directory trees with configurable depth.
* 🏷 **Extension Filtering** – Target only specific file types (e.g., `.exe`, `.dll`).
* 📝 **Detailed Reports** – Generates readable scan reports and can save them to a file.
* 🧾 **Verbose Mode** – View detailed debug logs and matches in real time.

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/yara-directory-scanner.git
cd yara-directory-scanner
pip install -r requirements.txt
```

**Dependencies:**

* `yara-python`
* `requests`
* `tqdm`

Install with:

```bash
pip install requirments.txt
```

---

## 🚀 Usage

### Basic Scan (Using Local Rules)

```bash
python yara_scanner.py /path/to/scan
```

If you already have rules saved in the `rules/` folder, they will be automatically used.

---

### Download Rules and Scan

```bash
python yara_scanner.py /path/to/scan
```

You will be prompted to enter rule URLs:

```
=== YARA Rule Downloader ===
Enter YARA rule URLs (space or comma separated) or press ENTER to use local rules: 
https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar
```

---

### Filter by File Extensions

```bash
python yara_scanner.py /path/to/scan --extensions exe dll pdf
```

This will only scan `.exe`, `.dll`, and `.pdf` files.

---

### Save Report to a File

```bash
python yara_scanner.py /path/to/scan --output scan_report.txt
```

---

### Enable Verbose Mode

```bash
python yara_scanner.py /path/to/scan --verbose
```

This will print detailed logs, rule hits, and meta information to the console.

---

## 📊 Example Output

```
2025-08-24 10:35:21 - INFO - Rules compiled successfully
2025-08-24 10:35:21 - INFO - Found 10 files to scan
Scanning files: 100%|██████████████████████████| 10/10 [00:02<00:00,  4.87it/s]
2025-08-24 10:35:24 - INFO - Scan completed in 2.11 seconds

YARA Scan Report - 2025-08-24 10:35:24.123456
Files with matches: 2
Total rule hits: 3

File: /samples/malware.exe
  Rule: MALW_Eicar (Tags: malware, test)

File: /samples/suspicious.pdf
  Rule: PDF_Shellcode (Tags: exploit)
```

---

## 📁 Project Structure

```
.
├── yara_scanner.py        # Main scanner script
├── rules/                 # Downloaded or local yara rules
├── requirements.txt       # Dependencies
└── README.md              # Documentation
```

---

## 🛡 Use Cases

* 🔎 Hunting for known malware samples in a folder of files
* 🧪 Quickly triaging suspicious samples in a malware lab
* 📂 Scanning backups or downloads for threats
* 🧰 Building automation pipelines for SOC or DFIR teams

---

## ⚠️ Disclaimer

This tool is meant for **educational and research purposes**.
Ensure you have permission to scan files or directories before running it on production systems.

---
