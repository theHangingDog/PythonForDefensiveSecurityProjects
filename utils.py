
import os
import re
import requests
import json
from datetime import datetime
from database import store_ioc_data  # Import for ioc_correlation
from config import logger  # Import logger from config

def fetch_daily_feeds():
    feeds = []
    abusech_key = os.getenv("ABUSECH_API_KEY", "")
    if not abusech_key:
        logger.warning("ABUSECH_API_KEY missing - Skipping MalwareBazaar and URLhaus (register at https://auth.abuse.ch/ for a free key)")
    sources = {
        "AlienVault OTX": {
            "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "method": "GET",
            "headers": {
                "X-OTX-API-KEY": os.getenv("ALIENVAULT_API_KEY", "")
            }
        },
        "MalwareBazaar": {
            "url": "https://mb-api.abuse.ch/api/v1/",
            "method": "POST",
            "data": {
                "query": "get_recent",
                "selector": "100"
            },
            "headers": {"Auth-Key": abusech_key} if abusech_key else {}
        },
        "URLhaus Recent URLs": { # Added: Recent malicious URLs
            "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
            "method": "GET",
            "headers": {"Auth-Key": abusech_key} if abusech_key else {}
        },
        "DShield Blocklist": { # Added: IP blocklist
            "url": "https://www.dshield.org/block.txt",
            "method": "GET",
            "headers": {}
        }
    }
    alienvault_key = os.getenv("ALIENVAULT_API_KEY", "")
    if not alienvault_key:
        logger.warning("Skipping AlienVault OTX - API key missing")
        del sources["AlienVault OTX"] # Remove from sources if no key
    for name, config in sources.items():
        try:
            headers = config.get("headers", {})
            if config["method"] == "GET":
                response = requests.get(config["url"], headers=headers, timeout=30)
            elif config["method"] == "POST":
                response = requests.post(config["url"], data=config.get("data", {}), headers=headers, timeout=30)
            else:
                logger.warning(f"Unsupported HTTP method for {name}")
                continue
            if response.status_code == 200:
                try:
                    data = response.json()
                    feeds.append({"source": name, "data": data})
                    logger.info(f"Successfully fetched and parsed feed from {name}")
                except ValueError:
                    feeds.append({"source": name, "data": response.text})
                    logger.info(f"Fetched feed from {name} (non-JSON response)")
            else:
                logger.warning(f"{name} returned status {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as re:
            logger.exception(f"Request error fetching {name}: {re}")
    return feeds

def detect_ioc_type(ioc): # Merged detect_indicator_type into this (removed duplicate)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32}$", ioc.lower()): # Made case-insensitive
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{40}$", ioc.lower()):
        return "sha1"
    elif re.match(r"^[a-fA-F0-9]{64}$", ioc.lower()):
        return "sha256"
    elif re.match(r"^(https?://)?[\w.-]+\.[a-zA-Z]{2,}", ioc.lower()): # Improved URL/domain handling
        return "url" if ioc.lower().startswith("http") else "domain"
    else:
        return "unknown"

def parse_feed_data(feeds):
    try:
        normalized_data = []
        seen_indicators = set()
        for feed in feeds:
            source = feed.get("source")
            raw_data = feed.get("data")
            if source == "MalwareBazaar":
                if isinstance(raw_data, dict) and "data" in raw_data:
                    entries = raw_data["data"]
                    for entry in entries:
                        indicator = entry.get("sha256_hash")
                        if indicator and indicator.lower() not in seen_indicators:
                            normalized_data.append({
                                "source": source,
                                "indicator": indicator,
                                "type": "sha256", # Fixed type for hashes
                                "metadata": entry
                            })
                            seen_indicators.add(indicator.lower())
            elif source == "AlienVault OTX":
                if isinstance(raw_data, dict) and "results" in raw_data:
                    for pulse in raw_data["results"]:
                        for ind in pulse.get("indicators", []):
                            indicator = ind.get("indicator")
                            if indicator and indicator.lower() not in seen_indicators:
                                ioc_type = ind.get("type", "").lower() or detect_ioc_type(indicator)
                                normalized_data.append({
                                    "source": source,
                                    "indicator": indicator,
                                    "type": ioc_type,
                                    "metadata": ind
                                })
                                seen_indicators.add(indicator.lower())
            elif isinstance(raw_data, str):
                for line in raw_data.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and line.lower() not in seen_indicators:
                        normalized_data.append({
                            "source": source,
                            "indicator": line,
                            "type": detect_ioc_type(line),
                            "metadata": {}
                        })
                        seen_indicators.add(line.lower())
        logger.info(f"Parsed {len(normalized_data)} unique indicators from feeds")
        return normalized_data
    except Exception as e:
        logger.exception(f"Error in parse_feed_data: {e}")
        return []

def check_ip_reputation(ip):
    """Check IP reputation from multiple sources"""
    try:
        results = {}
        alienvault_key = os.getenv("ALIENVAULT_API_KEY", "")
        virustotal_key = os.getenv("VT_API_KEY", "")
        apis = {
            "AlienVault OTX": {
                "url": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                "headers": {"X-OTX-API-KEY": alienvault_key} if alienvault_key else {},
                "method": "GET"
            },
            "VirusTotal": {
                "url": f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                "headers": {"x-apikey": virustotal_key} if virustotal_key else {},
                "method": "GET"
            }
        }
        # Remove FireHOL from the APIs since it returns HTML
        # If you want to include FireHOL, we'd need to parse the HTML or find a proper API endpoint
        for name, config in apis.items():
            try:
                if config["method"] == "GET":
                    response = requests.get(config["url"], headers=config["headers"], timeout=30)
                else:
                    logger.warning(f"{name} uses unsupported HTTP method")
                    continue
                if response.status_code == 200:
                    try:
                        results[name] = response.json()
                        logger.info(f"{name} reputation lookup successful for {ip}")
                    except ValueError:
                        # If it's not JSON, check if it's useful text
                        if "html" not in response.text.lower() and "doctype" not in response.text.lower():
                            results[name] = {"data": response.text[:500]} # Limit text length
                        else:
                            results[name] = {"error": "HTML response received (not usable data)"}
                else:
                    results[name] = {"error": f"HTTP {response.status_code}"}
                    logger.warning(f"{name} returned status {response.status_code} for {ip}")
            except requests.exceptions.RequestException as re:
                results[name] = {"error": str(re)}
                logger.error(f"{name} request error for {ip}: {re}")
        return results
    except Exception as e:
        logger.error(f"Error in check_ip_reputation: {e}")
        return {}

def check_domain_reputation(domain):
    try:
        results = {}
        alienvault_key = os.getenv("ALIENVAULT_API_KEY")
        virustotal_key = os.getenv("VT_API_KEY")
        phishtank_key = os.getenv("PHISHTANK_APP_KEY", "") # Optional
        abusech_key = os.getenv("ABUSECH_API_KEY", "") # Required for URLhaus
        if not alienvault_key:
            logger.warning("ALIENVAULT_API_KEY missing")
        if not virustotal_key:
            logger.warning("VT_API_KEY missing")
        if not abusech_key:
            logger.warning("ABUSECH_API_KEY missing - Skipping URLhaus (register at https://auth.abuse.ch/ for free key)")
        apis = {
            "AlienVault OTX": {
                "url": f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                "method": "GET",
                "headers": {"X-OTX-API-KEY": alienvault_key} if alienvault_key else None,
                "data": None
            },
            "URLhaus": {
                "url": "https://urlhaus-api.abuse.ch/v1/host/",
                "method": "POST",
                "headers": {"Auth-Key": abusech_key} if abusech_key else {},
                "data": {"host": domain} if abusech_key else None
            },
            "VirusTotal": {
                "url": f"https://www.virustotal.com/api/v3/domains/{domain}",
                "method": "GET",
                "headers": {"x-apikey": virustotal_key} if virustotal_key else None,
                "data": None
            }
        }
        for name, config in apis.items():
            if (config.get("headers") is None and config["method"] == "GET") or (name == "URLhaus" and not abusech_key):
                results[name] = {"error": "API key required or invalid"}
                continue
            try:
                if config["method"] == "GET":
                    response = requests.get(config["url"], headers=config.get("headers", {}), timeout=30)
                elif config["method"] == "POST":
                    response = requests.post(config["url"], headers=config.get("headers", {}), data=config["data"], timeout=30)
                else:
                    logger.warning(f"{name} uses unsupported HTTP method")
                    continue
                if response.status_code == 200:
                    try:
                        results[name] = response.json()
                        logger.info(f"{name} reputation lookup successful for {domain}")
                    except ValueError:
                        results[name] = {"raw": response.text}
                        logger.warning(f"{name} returned non-JSON response for {domain}")
                else:
                    results[name] = {"error": f"HTTP {response.status_code}: {response.text[:100]}..."}
                    logger.warning(f"{name} returned status {response.status_code} for {domain}")
            except requests.exceptions.RequestException as re:
                results[name] = {"error": str(re)}
                logger.exception(f"{name} request error for {domain}: {re}")
        return results
    except Exception as e:
        logger.exception(f"Error in check_domain_reputation: {e}")
        return {}

def check_hash_reputation(file_hash):
    try:
        results = {}
        vt_key = os.getenv("VT_API_KEY")
        abusech_key = os.getenv("ABUSECH_API_KEY", "")
        if not vt_key:
            logger.warning("VT_API_KEY missing")
        apis = {
            "VirusTotal": {
                "url": f"https://www.virustotal.com/api/v3/files/{file_hash}",
                "method": "GET",
                "headers": {"x-apikey": vt_key} if vt_key else None,
                "data": None # Renamed
            },
            "MalwareBazaar": {
                "url": "https://mb-api.abuse.ch/api/v1/",
                "method": "POST",
                "headers": {},
                "data": { # Renamed from "json"
                    "query": "get_info",
                    "hash": file_hash
                },
                "headers": {"Auth-Key": abusech_key} if abusech_key else {}
            }
        }
        for name, config in apis.items():
            if config.get("headers") is None and config["method"] == "GET":
                results[name] = {"error": "API key missing"}
                continue
            try:
                if config["method"] == "GET":
                    response = requests.get(config["url"], headers=config.get("headers", {}), timeout=30)
                elif config["method"] == "POST":
                    response = requests.post(config["url"], headers=config.get("headers", {}), data=config["data"], timeout=30) # Changed
                else:
                    logger.warning(f"{name} uses unsupported HTTP method")
                    continue
                if response.status_code == 200:
                    try:
                        results[name] = response.json()
                        logger.info(f"{name} reputation lookup successful for {file_hash}")
                    except ValueError:
                        results[name] = {"raw": response.text}
                        logger.warning(f"{name} returned non-JSON response for {file_hash}")
                else:
                    results[name] = {"error": f"HTTP {response.status_code}"}
                    logger.warning(f"{name} returned status {response.status_code} for {file_hash}")
            except requests.exceptions.RequestException as re:
                results[name] = {"error": str(re)}
                logger.exception(f"{name} request error for {file_hash}: {re}")
        return results
    except Exception as e:
        logger.exception(f"Error in check_hash_reputation: {e}")
        return {}

def ioc_correlation(ioc):
    try:
        results = {}
        ioc_type = detect_ioc_type(ioc)
        logger.info(f"Detected IOC type: {ioc_type} for {ioc}")
        if ioc_type == "ip":
            results = check_ip_reputation(ioc)
        elif ioc_type in {"md5", "sha1", "sha256"}:
            results = check_hash_reputation(ioc)
        elif ioc_type == "domain":
            results = check_domain_reputation(ioc)
        else:
            logger.warning(f"Unsupported or malformed IOC: {ioc}")
            return {
                "ioc": ioc,
                "type": ioc_type,
                "results": {},
                "confidence_score": 0,
                "sources_checked": 0
            }
        confidence_score = 0
        sources_checked = len(results)
        for source, data in results.items():
            if isinstance(data, dict) and "error" not in data and bool(data): # Added bool(data) to avoid empty dicts
                confidence_score += 1
        score = round((confidence_score / sources_checked) * 100, 2) if sources_checked > 0 else 0
        logger.info(f"IOC {ioc} correlation confidence score: {score}%")
        correlation_data = {
            "ioc": ioc,
            "type": ioc_type,
            "results": results,
            "confidence_score": score,
            "sources_checked": sources_checked
        }
        store_ioc_data(correlation_data) # Added call to store IOC data
        return correlation_data
    except Exception as e:
        logger.exception(f"Error in ioc_correlation: {e}")
        return {
            "ioc": ioc,
            "type": "error",
            "results": {},
            "confidence_score": 0,
            "sources_checked": 0
        }