#!/usr/bin/env python3
"""
Basic usage example for octodns-azion provider

This example shows how to:
1. Initialize the Azion provider
2. List available zones
3. Populate a zone with records
"""

import os
import warnings

# Suppress urllib3 SSL warnings
warnings.filterwarnings("ignore", message=".*urllib3.*")
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

from octodns.zone import Zone
from octodns_azion import AzionProvider


def main():
    # Get API token from environment
    token = os.environ.get("AZION_TOKEN")
    if not token:
        print("Please set AZION_TOKEN environment variable")
        return

    # Initialize the provider
    provider = AzionProvider("azion", token)

    # List available zones
    print("Available zones:")
    zones = provider.list_zones()
    for zone in zones:
        print(f"  - {zone}")

    if not zones:
        print("No zones found. Please create a zone in Azion Console first.")
        return

    # Example: List all zone records
    for zone in zones:
        print(f"\nWorking with zone: {zone}")

        # Create a zone object
        zone = Zone(zone, [])

        # Populate the zone with existing records
        exists = provider.populate(zone)
        print(f"Zone exists: {exists}")
        print(f"Found {len(zone.records)} records:")

        for record in zone.records:
            print(f"  - {record.fqdn} {record._type} {record.ttl} {record.data}")


if __name__ == "__main__":
    main()
