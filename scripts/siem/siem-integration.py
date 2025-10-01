#!/usr/bin/env python3
"""
Secure ICS SIEM Integration Connector

Collects ICS security logs and forwards events to a SIEM (Splunk/Elasticsearch) safely.

Author: Ali AlEnezi
License: MIT
Version: 1.0.0
"""

import os
import sys
import json
import argparse
import logging
import time
from typing import List, Dict
from datetime import datetime
import requests
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


class SecureSIEMConnector:
    """Secure connector to forward ICS events to SIEM platforms."""

    def __init__(self, platform: str, endpoint: str, token: str):
        self.platform = platform.lower()
        self.endpoint = endpoint
        self.token = token
        if not self.token:
            logger.error("SIEM token not provided. Use environment variable SIEM_TOKEN.")
            sys.exit(1)

    def _prepare_event(self, event: Dict) -> Dict:
        """Prepare event payload."""
        return {
            "timestamp": event.get("timestamp", datetime.utcnow().isoformat()),
            "host": event.get("host", os.uname().nodename),
            "source": "ics-hardening-framework",
            "event": event
        }

    def _post_request(self, url: str, payload: Dict, headers: Dict) -> bool:
        """Send HTTP POST with retries."""
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=5, verify=True)
                if response.status_code in (200, 201, 202):
                    return True
                else:
                    logger.warning(f"Attempt {attempt}: HTTP {response.status_code}")
            except requests.RequestException as e:
                logger.warning(f"Attempt {attempt}: {e}")
            time.sleep(RETRY_DELAY * attempt)
        return False

    def send_to_splunk(self, event: Dict) -> bool:
        """Send event to Splunk HEC."""
        payload = self._prepare_event(event)
        headers = {"Authorization": f"Splunk {self.token}", "Content-Type": "application/json"}
        return self._post_request(self.endpoint, payload, headers)

    def send_to_elasticsearch(self, event: Dict, index: str) -> bool:
        """Send event to Elasticsearch."""
        payload = self._prepare_event(event)
        url = f"{self.endpoint.rstrip('/')}/{index}/_doc"
        headers = {"Content-Type": "application/json"}
        return self._post_request(url, payload, headers)

    def send_events(self, events: List[Dict], index: str = "ics-events") -> None:
        """Send batch of events to SIEM."""
        success_count = 0
        for event in events:
            if self.platform == "splunk":
                if self.send_to_splunk(event):
                    success_count += 1
            elif self.platform == "elasticsearch":
                if self.send_to_elasticsearch(event, index):
                    success_count += 1
            else:
                logger.error(f"Unsupported platform: {self.platform}")
                break
        logger.info(f"Sent {success_count}/{len(events)} events to {self.platform}")


def load_events(file_path: str) -> List[Dict]:
    """Load events from JSON file."""
    path = Path(file_path)
    if not path.exists():
        logger.error(f"Event file does not exist: {file_path}")
        sys.exit(1)

    # Warn if file permissions are too open
    if os.name != 'nt' and oct(path.stat().st_mode)[-3:] != '600':
        logger.warning(f"Event file {file_path} has loose permissions. Consider chmod 600.")

    try:
        with open(path, 'r') as f:
            events = json.load(f)
            if not isinstance(events, list):
                raise ValueError("JSON file must contain an array of events")
            return events
    except Exception as e:
        logger.error(f"Failed to load events: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Secure ICS SIEM Integration Connector")
    parser.add_argument("--platform", "-p", required=True, choices=["splunk", "elasticsearch"], help="SIEM platform")
    parser.add_argument("--endpoint", "-e", required=True, help="SIEM API endpoint")
    parser.add_argument("--file", "-f", required=True, help="JSON file with events")
    parser.add_argument("--index", "-i", default="ics-events", help="Elasticsearch index name")
    args = parser.parse_args()

    token = os.getenv("SIEM_TOKEN")
    if not token:
        logger.error("Environment variable SIEM_TOKEN is not set. Exiting.")
        sys.exit(1)

    events = load_events(args.file)
    if not events:
        logger.error("No events found. Exiting.")
        sys.exit(1)

    connector = SecureSIEMConnector(platform=args.platform, endpoint=args.endpoint, token=token)
    connector.send_events(events, index=args.index)


if __name__ == "__main__":
    main()
