#!/usr/bin/env python3
"""
Anti-Analysis & Evasion Technique Detector
-----------------------------------------
This script scans binaries or text files for known strings and API calls
commonly used for:
    - Anti-VM techniques
    - Debugger detection
    - Timing-based evasion
    - Sandbox evasion
    - Process injection
    - User interaction checks
    - Environment fingerprinting
"""

import argparse
import os


def read_file_content(file_path: str) -> str:
    """Reads and decodes file content safely."""
    try:
        with open(file_path, "rb") as f:
            return f.read().decode(errors="ignore")
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found.")
        return ""
    except Exception as e:
        print(f"[!] Could not read file: {e}")
        return ""


def detect_patterns(content: str, patterns: list, category: str) -> list:
    """Generic function to search for patterns in file content."""
    matches = [p for p in patterns if p.lower() in content.lower()]
    if matches:
        print(f"[+] {category} Detected:")
        for match in matches:
            print(f"    - {match}")
    else:
        print(f"[-] No {category} found.")
    return matches


def run_evasion_analysis(file_path: str) -> dict:
    """Runs a full anti-analysis & evasion technique check."""
    content = read_file_content(file_path)
    if not content:
        return {}

    print("\n=== [+] Anti-Analysis & Evasion Checks [+] ===\n")

    results = {
        "vm_indicators": detect_patterns(content, [
            "VBox", "VMware", "vboxservice", "vboxtray",
            "qemu", "VirtualBox", "virtual_machine",
            "vmtools", "vmguest", "Xen"
        ], "VM Indicators"),

        "timing_apis": detect_patterns(content, [
            "Sleep", "GetTickCount", "QueryPerformanceCounter",
            "NtDelayExecution", "RDTSC", "timeGetTime"
        ], "Timing-Based Evasion APIs"),

        "debugger_apis": detect_patterns(content, [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString",
            "FindWindow", "CloseHandle"
        ], "Debugger Detection APIs"),

        "interaction_apis": detect_patterns(content, [
            "GetCursorPos", "GetAsyncKeyState", "GetForegroundWindow",
            "GetLastInputInfo", "ShowCursor", "mouse_event", "keybd_event"
        ], "User Interaction Checks"),

        "injection_apis": detect_patterns(content, [
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext"
        ], "Process Injection APIs"),

        "environment_apis": detect_patterns(content, [
            "GetSystemMetrics", "GetEnvironmentVariable",
            "GetComputerName", "GetUserName",
            "GetAdaptersInfo", "GetVolumeInformation"
        ], "Environment Fingerprinting APIs"),

        "sandbox_apis": detect_patterns(content, [
            "NtSetInformationThread", "NtQuerySystemInformation",
            "NtQueryObject", "NtQueryInformationThread",
            "NtQueryInformationToken"
        ], "Sandbox Evasion APIs")
    }

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan a file for anti-analysis and evasion techniques."
    )
    parser.add_argument(
        "file",
        help="Path to the file you want to scan."
    )
    args = parser.parse_args()

    if os.path.isfile(args.file):
        run_evasion_analysis(args.file)
    else:
        print(f"[!] File '{args.file}' does not exist.")
