#!/usr/bin/env python3

from api import client
import json
from typing import Dict, Any


def print_response(response: Dict[str, Any]) -> None:
    """Pretty print API response."""
    print(json.dumps(response, indent=2))


def main():
    try:
        print("Getting network devices...")
        devices = client.get_dna_intent_api_v1_network_device(
            limit=10,          # Get up to 10 devices
            offset=1           # Start from first record
        )
        print_response(devices)

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
