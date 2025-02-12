#!/usr/bin/env python3

from api import client
from api.outputhelper import OutputHelper
import json
from typing import Dict, Any
import logging

# Set up debug logging
logging.basicConfig(level=logging.DEBUG)
requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


def print_response(response: Dict[str, Any]) -> None:
    """Pretty print API response."""
    print(json.dumps(response, indent=2))


def main():
    try:
        print(f"Using DNAC host: {client.host}")
        print("Getting network devices...")
        devices = client.get_dna_intent_api_v1_network_device(
            limit=10,          # Get up to 10 devices
            offset=1           # Start from first record
        )
        
        # Print the response
        print_response(devices)
        
        # Convert to CSV
        output = OutputHelper(devices)
        csv_file = output.to_csv()
        print(f"\nData exported to: {csv_file}")

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
