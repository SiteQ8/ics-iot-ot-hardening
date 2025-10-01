#!/usr/bin/env python3
"""
ICS Standards Compliance Checker

Validates ICS/OT environments against the Central Bank of Kuwait (CBK) Cybersecurity Framework (CSF).

Author: Ali AlEnezi
License: MIT
Version: 1.2.0
"""

import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List
from tabulate import tabulate  # for console summary

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def load_cbk_controls(file_path: Path) -> Dict[str, List[str]]:
    """Load CBK CSF controls from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            controls = json.load(f)
            if not all(isinstance(v, list) for v in controls.values()):
                raise ValueError("Each function must map to a list of controls.")
            return controls
    except Exception as e:
        logger.error(f"Failed to load CBK CSF controls: {e}")
        raise

def load_implementation(file_path: Path) -> Dict[str, List[str]]:
    """Load implemented controls from JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return {k: v for k, v in data.items() if isinstance(v, list)}
    except Exception as e:
        logger.error(f"Failed to load implementation file: {e}")
        raise

def check_compliance(cbk_controls: Dict[str, List[str]], implemented: Dict[str, List[str]]) -> Dict[str, Dict]:
    """Compare implemented vs required controls."""
    report = {}
    total_required = 0
    total_implemented = 0

    for function, controls in cbk_controls.items():
        required = set(controls)
        impl = set(implemented.get(function, []))
        missing = required - impl
        extra = impl - required

        compliance_percent = round((len(impl & required) / len(required)) * 100, 1) if required else 0

        report[function] = {
            "required": sorted(required),
            "implemented": sorted(impl),
            "missing": sorted(missing),
            "extra": sorted(extra),
            "compliance_percent": compliance_percent
        }

        total_required += len(required)
        total_implemented += len(impl & required)

    overall_percent = round((total_implemented / total_required) * 100, 1) if total_required else 0
    report["OverallCompliance"] = {
        "percent": overall_percent,
        "required": total_required,
        "implemented": total_implemented
    }
    return report

def save_report(report: Dict, output_file: Path):
    """Save compliance report to JSON."""
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Compliance report saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        raise

def colorize_missing(count: int) -> str:
    """Return a color based on missing control count."""
    if count == 0:
        return f"{GREEN}{count}{RESET}"
    elif count <= 2:
        return f"{YELLOW}{count}{RESET}"
    else:
        return f"{RED}{count}{RESET}"

def print_summary(report: Dict):
    """Print a concise console summary of compliance with highlights."""
    rows = []
    for function, data in report.items():
        if function == "OverallCompliance":
            continue
        rows.append([function, f"{data['compliance_percent']}%", colorize_missing(len(data['missing']))])
    table = tabulate(rows, headers=["Function", "Compliance %", "Missing Controls"], tablefmt="grid")
    print("\nICS CBK CSF Compliance Summary:\n")
    print(table)
    overall = report.get("OverallCompliance", {}).get("percent", 0)
    print(f"\nOverall CBK CSF Compliance: {overall}%\n")

def main():
    parser = argparse.ArgumentParser(description="CBK CSF Compliance Checker for ICS environments")
    parser.add_argument("--cbk-controls", "-c", required=True, help="JSON file of CBK CSF standard controls")
    parser.add_argument("--implementation", "-i", required=True, help="JSON file of implemented controls")
    parser.add_argument("--output", "-o", help="Output report JSON file", default="cbk_csf_compliance_report.json")
    args = parser.parse_args()

    cbk_file = Path(args.cbk_controls)
    impl_file = Path(args.implementation)
    output_file = Path(args.output)

    if not cbk_file.exists():
        logger.error(f"CBK controls file not found: {cbk_file}")
        return 1
    if not impl_file.exists():
        logger.error(f"Implementation file not found: {impl_file}")
        return 1

    try:
        cbk_controls = load_cbk_controls(cbk_file)
        implemented = load_implementation(impl_file)
        report = check_compliance(cbk_controls, implemented)
        save_report(report, output_file)
        print_summary(report)
    except Exception:
        logger.error("Compliance check failed.")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
