#!/usr/bin/env python3

from api import client
from api.outputhelper import OutputHelper
import json
from typing import Dict, Any, List
import logging
import csv
from difflib import SequenceMatcher


# Set up debug logging
logging.basicConfig(level=logging.DEBUG)
requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


def find_best_match(target: str, candidates: List[str]) -> str:
    """Find the best match in a list of candidates for a given target string."""
    best_match = None
    best_ratio = 0
    for candidate in candidates:
        ratio = SequenceMatcher(None, target, candidate).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = candidate
    return best_match


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


def update_inventory(csv_data: List[Dict[str, str]], devices: List[Dict[str, Any]]) -> None:
    """Update inventory counts in CSV data.
    
    Args:
        csv_data (List[Dict[str, str]]): Existing CSV data
        devices (List[Dict[str, Any]]): Device list from DNA Center
    """
    # Make the column name search case-insensitive
    title_column = next((col for col in csv_data[0].keys() if col.lower() == 'title'), None)
    if not title_column:
        print("Error: Could not find 'Title' column in CSV")
        return

    print("\nFull device data structure for first few devices:")
    for device in devices[:3]:  # Show first 3 devices
        print("\n" + "="*50)
        print(json.dumps(device, indent=2))
        print("="*50)

    # Process each device
    device_counts = {}  # Track counts per site
    matched_sites = []  # Track which sites were matched to CSV
    all_models = set()  # Track all unique models found
    
    for device in devices:
        try:
            hostname = device.get('hostname', '')
            if not hostname:
                print(f"WARNING: No hostname found for device ({device.get('platformId', 'Unknown')})")
                continue

            # Get site from hostname prefix
            site_name = get_site_from_hostname(hostname)
            model = categorize_device(device)
            if model:  # Only count switches
                if site_name not in device_counts:
                    device_counts[site_name] = {}
                if model not in device_counts[site_name]:
                    device_counts[site_name][model] = 0
                device_counts[site_name][model] += 1
                all_models.add(model)
                print(f"Found {model} at site '{site_name}'")
        except Exception as e:
            print(f"Error processing device: {e}")
            print(f"Device: {device.get('hostname', 'Unknown')} ({device.get('platformId', 'Unknown')})")
            continue

    # Update CSV with counts
    for site_name, counts in device_counts.items():
        try:
            # Get list of existing titles
            csv_titles = [row[title_column].strip() for row in csv_data]
            best_match_title = find_best_match(site_name, csv_titles)

            if best_match_title:
                matched_sites.append(site_name)  # Track that this site was matched
                for row in csv_data:
                    if row[title_column].strip() == best_match_title:
                        try:
                            # Map models to CSV categories
                            csv_counts = {
                                "Distribution Routers": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['9300', '9500'])),
                                "48 Port Switches": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['48p', '48-port', '48port', '48t', '-48'])),
                                "24 Port Switches": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['24p', '24-port', '24port', '24t', '-24']))
                            }
                            
                            # Update CSV with categorized counts
                            for category, count in csv_counts.items():
                                if count > 0:
                                    current_count = int(row.get(category, "0") or "0")
                                    row[category] = str(current_count + count)
                                    print(f"Updated {category} count for '{best_match_title}' (+{count})")
                        except ValueError as e:
                            print(f"Error converting values for row '{best_match_title}': {e}")
                        break
            else:
                print(f"No matching row found for site '{site_name}'")
                print(f"Device counts that would have been added: {counts}")
        except Exception as e:
            print(f"Error processing site {site_name}: {e}")
            continue
    
    # Write detailed inventory report
    write_inventory_report(devices)


def main():
    try:
        print(f"Using DNAC host: {client.host}")
        
        # Read existing CSV data
        csv_data = []
        try:
            with open("input.csv", "r") as csvfile:
                reader = csv.DictReader(csvfile)
                csv_data = list(reader)
        except FileNotFoundError:
            print("Error: input.csv not found")
            return 1
        
        # Get list of network devices from DNA Center
        print("Getting network devices...")
        response = client.get_dna_intent_api_v1_network_device()
        devices = response.get('response', [])
        
        # Update inventory counts
        update_inventory(csv_data, devices)
        
        # Write updated data back to CSV
        with open("input.csv", "w", newline="") as csvfile:
            fieldnames = csv_data[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_data)
        
        print("\nSuccessfully updated input.csv")
        client.close()

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
