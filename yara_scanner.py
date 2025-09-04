#!/usr/bin/env python3
import os
import logging
import argparse
from datetime import datetime
from typing import List, Dict, Any
import time
import yara
import requests
from tqdm import tqdm


def download_rules(sources: List[str]) -> List[str]:
    
    os.makedirs("rules", exist_ok=True)
    downloaded_paths = []
    
    for url in sources:
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            
            filename = os.path.basename(url) or "rules.yar"
            if not filename.endswith(('.yar', '.yara')):
                filename += '.yar'
                
            local_path = os.path.join("rules", filename)
            
            with open(local_path, "w", encoding='utf-8') as f:
                f.write(response.text)
                
            downloaded_paths.append(local_path)
            logging.info("Downloaded rules from %s", url)
            
        except Exception as e:
            logging.error("Failed to download from %s: %s", url, str(e))
    
    return downloaded_paths

def compile_rules(rule_paths: List[str]) -> yara.Rules:
    
    if not rule_paths:
        raise ValueError("No rule files provided")
    
    rule_dict = {f"ruleset_{i}": path for i, path in enumerate(rule_paths)}
    return yara.compile(filepaths=rule_dict)

def scan_file(file_path: str, rules: yara.Rules) -> Dict[str, Any]:
    
    try:
        matches = rules.match(file_path)
        if not matches:
            return {"file_path": file_path, "matches": []}
        
        matches_details = []
        for match in matches:
            details = {
                "rule": match.rule,
                "namespace": match.namespace,
                "meta": dict(match.meta),
                "tags": list(match.tags),
                "strings": match.strings
            }
                
            matches_details.append(details)
            
        logging.debug("Found %d matches in %s", len(matches_details), file_path)
        return {"file_path": file_path, "matches": matches_details}
        
    except yara.Error as e:
        logging.error("YARA error scanning %s: %s", file_path, str(e))
    except PermissionError:
        logging.warning("Permission denied: %s", file_path)
    except Exception as e:
        logging.error("Error scanning %s: %s", file_path, str(e))
    
    return {"file_path": file_path, "matches": []}


def find_files(directory: str, max_depth: int = 5, extensions: List[str] = None) -> List[str]:
    
    file_list = []
    
    for root, dirs, files in os.walk(directory):
        # Check depth
        current_depth = root[len(directory):].count(os.sep)
        if current_depth > max_depth:
            continue
            
        for file in files:
            file_path = os.path.join(root, file)
            if extensions:
                ext = os.path.splitext(file)[1].lower()
                if ext in extensions:
                    file_list.append(file_path)
            else:
                file_list.append(file_path)
                
    return file_list

def scan_directory(directory: str, rule_paths: List[str], 
                  max_depth: int = 5, extensions: List[str] = None) -> List[Dict[str, Any]]:
    
    if not os.path.isdir(directory):
        raise ValueError(f"Directory not found: {directory}")
    
    # Find files to scan
    files = find_files(directory, max_depth, extensions)
    if not files:
        logging.info("No files found to scan")
        return []
    
    logging.info("Found %d files to scan", len(files))
    

    rules = compile_rules(rule_paths)
    results = []
    for file in tqdm(files, desc="Scanning files"):
        results.append(scan_file(file, rules))
    return [r for r in results if r["matches"]]
    
def generate_report(matches: List[Dict[str, Any]], output_file: str = None) -> str:
    
    if not matches:
        report = "No matches found during scan."
    else:
        total_hits = sum(len(m["matches"]) for m in matches)
        report = f"YARA Scan Report - {datetime.now()}\n"
        report += f"Files with matches: {len(matches)}\n"
        report += f"Total rule hits: {total_hits}\n\n"
        
        for match in matches:
            report += f"File: {match['file_path']}\n"
            for m in match["matches"]:
                report += f"  Rule: {m['rule']} (Tags: {', '.join(m['tags'])})\n"
            report += "\n"
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        logging.info("Report saved to %s", output_file)
    
    return report

def setup_logging(verbose: bool = False):
    
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def main():
    
    parser = argparse.ArgumentParser(description="Simple YARA file scanner")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--extensions", nargs="+", 
                       help="File extensions to scan (e.g., exe dll pdf)")
    parser.add_argument("--depth", type=int, default=5,
                       help="Maximum directory depth to scan")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    setup_logging(args.verbose)

    print("\n=== YARA Rule Downloader ===")
    rule_input = input(
        "Enter YARA rule URLs (space or comma separated) or press ENTER to use local rules: "
    ).strip()

    if rule_input:
        # Split by space or comma
        urls = [url.strip() for url in rule_input.replace(",", " ").split()]
        rule_paths = download_rules(urls)
    else:
        rule_paths = []

    if not rule_paths:
        if os.path.exists("rules"):
            rule_paths = [os.path.join("rules", f) for f in os.listdir("rules") 
                         if f.endswith(('.yar', '.yara'))]
        if not rule_paths:
            logging.error("No YARA rules available (neither downloaded nor found locally)")
            return

    # Validate rules
    try:
        compile_rules(rule_paths)
        logging.info("Rules compiled successfully")
    except Exception as e:
        logging.error("Failed to compile rules: %s", str(e))
        return

    # Prepare extensions
    extensions = None
    if args.extensions:
        extensions = [f".{ext.lower()}" if not ext.startswith('.') else ext.lower() 
                     for ext in args.extensions]

    # Scan directory
    start_time = time.time()
    matches = scan_directory(
        args.directory, 
        rule_paths, 
        args.depth, 
        extensions
    )
    duration = time.time() - start_time

    logging.info("Scan completed in %.2f seconds", duration)
    report = generate_report(matches, args.output)
    if args.verbose:
        print(report)

if __name__ == "__main__":
    main()