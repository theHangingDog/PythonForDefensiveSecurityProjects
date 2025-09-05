🛡️ Anti-Analysis & Evasion Technique Detector

A lightweight Python tool to scan binaries or text files for anti-analysis and evasion techniques used by malware.
It detects strings and API calls commonly associated with:

🖥️ VM & Sandbox Detection

🧵 Debugger Checks

⏱️ Timing-Based Evasion

🖱️ User Interaction Checks

💉 Process Injection APIs

🌍 Environment Fingerprinting

🚀 Features

✅ Detects Virtual Machine artifacts (VBox, VMware, QEMU)
✅ Identifies debugger detection APIs (IsDebuggerPresent, NtQueryInformationProcess, etc.)
✅ Finds timing-based evasion techniques (Sleep, RDTSC, etc.)
✅ Flags sandbox evasion and environment fingerprinting APIs
✅ CLI-based, fast, and easy to use

📦 Installation
git clone https://github.com/yourusername/anti-analysis-detector.git
cd anti-analysis-detector


Requires Python 3.7+ (no external dependencies).

⚡ Usage

Run the script against a file:

python3 detect_evasion.py path/to/suspicious/file.exe


Example Output:

=== [+] Anti-Analysis & Evasion Checks [+] ===

[+] VM Indicators Detected:
    - VBox
    - vmtools

[+] Debugger Detection APIs Detected:
    - IsDebuggerPresent
    - NtQueryInformationProcess

[-] No Sandbox Evasion APIs found.
[-] No User Interaction Checks found.

📚 Use Case

This tool is useful for:

Malware Analysts 🕵️

Reverse Engineers 🔬

Security Researchers 🛡️

Threat Hunters 🔎
