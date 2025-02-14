#!/usr/bin/env python3

from api import client
import json
from typing import Dict, Any, List
import logging

# Set up debug logging
logging.basicConfig(level=logging.DEBUG)
requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


def categorize_device(device: Dict[str, Any]) -> str:
    """Get device model information.
    
    Args:
        device (Dict[str, Any]): Device information from DNA Center
        
    Returns:
        str: Device model or None if not a switch
    """
    family = device.get('family', '').lower()
    series = device.get('series', '').lower()
    platform_id = device.get('platformId', '')
    
    # Only process switches
    if 'switch' in family or 'catalyst' in series:
        return platform_id
    
    return None


def get_site_from_hostname(hostname: str) -> str:
    """Extract site name from hostname prefix.
    
    Args:
        hostname (str): Device hostname
        
    Returns:
        str: Site name based on hostname prefix (part before first '-')
    """
    if not hostname:
        return "Unknown"
    
    # Split on '-' and take the first part
    parts = hostname.split('-')
    return parts[0] if parts else "Unknown"


def write_inventory_report(devices: List[Dict[str, Any]]) -> None:
    """Write detailed inventory report to a text file.
    
    Args:
        devices (List[Dict[str, Any]]): List of devices from DNA Center
    """
    try:
        # Group devices by site (hostname prefix)
        site_devices = {}
        
        for device in devices:
            hostname = device.get('hostname', '')
            if not hostname:
                continue
                
            site = get_site_from_hostname(hostname)
            if site not in site_devices:
                site_devices[site] = {}
            
            platform_id = device.get('platformId', 'Unknown')
            if platform_id not in site_devices[site]:
                site_devices[site][platform_id] = []
            
            # Store device details
            site_devices[site][platform_id].append({
                'hostname': hostname,
                'series': device.get('series', 'Unknown'),
                'family': device.get('family', 'Unknown'),
                'software': device.get('softwareVersion', 'Unknown')
            })

        # Write the report
        with open("dnac_inventory.txt", "w") as f:
            f.write("DNA Center Inventory Report\n")
            f.write("=========================\n\n")
            
            # List all sites and their devices
            for site in sorted(site_devices.keys()):
                # Make site header more prominent
                f.write("\n" + "="*50 + "\n")
                f.write(f"SITE: {site}\n")
                f.write("="*50 + "\n")
                
                # Count totals for this site
                model_counts = {}
                for platform_id, devices in site_devices[site].items():
                    model_counts[platform_id] = len(devices)
                
                # Print summary counts for site
                f.write("\nDevice Counts:\n")
                f.write("-" * 13 + "\n")
                for platform_id, count in sorted(model_counts.items()):
                    f.write(f"  {platform_id}: {count}\n")
                
                # Print detailed device information
                f.write("\nDetailed Device List:\n")
                f.write("-" * 19 + "\n")
                for platform_id, devices in sorted(site_devices[site].items()):
                    f.write(f"\n  {platform_id}:\n")
                    for device in sorted(devices, key=lambda x: x['hostname']):
                        f.write(f"    - {device['hostname']}\n")
                        f.write(f"      Series: {device['series']}\n")
                        f.write(f"      Family: {device['family']}\n")
                        f.write(f"      Software: {device['software']}\n")
                        f.write("\n")  # Add space between devices
            
            # Add overall summary
            f.write("\n" + "="*50 + "\n")
            f.write("OVERALL SUMMARY\n")
            f.write("=" * 50 + "\n")
            f.write(f"\nTotal Sites: {len(site_devices)}\n")
            
            # Count total devices by model across all sites
            total_counts = {}
            for site_data in site_devices.values():
                for platform_id, devices in site_data.items():
                    if platform_id not in total_counts:
                        total_counts[platform_id] = 0
                    total_counts[platform_id] += len(devices)
            
            f.write("\nTotal Devices by Model:\n")
            f.write("-" * 21 + "\n")
            for platform_id, count in sorted(total_counts.items()):
                f.write(f"  {platform_id}: {count}\n")
        
        print(f"\nDetailed inventory report written to dnac_inventory.txt")
    except Exception as e:
        print(f"Error writing inventory report: {e}")


def main():
    try:
        print(f"Using DNAC host: {client.host}")
        
        # Get list of network devices from DNA Center
        print("Getting network devices...")
        response = client.get_dna_intent_api_v1_network_device()
        devices = response.get('response', [])
        
        # Generate inventory report
        write_inventory_report(devices)
        
        client.close()

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
