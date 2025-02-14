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
    """Categorize device based on its properties.
    
    Args:
        device (Dict[str, Any]): Device information from DNA Center
        
    Returns:
        str: Device category or None if not a switch
    """
    family = device.get('family', '').lower()
    series = device.get('series', '').lower()
    model = device.get('platformId', '').lower()
    
    # Check if it's a switch
    if 'switch' in family or 'catalyst' in series:
        # Distribution switches (typically 9300/9500 series)
        if any(x in model for x in ['9300', '9500']):
            return "Distribution Routers"  # Keep the CSV column name as is
        
        # 48-port switches
        if any(x in model for x in ['48p', '48-port', '48port', '48t', '-48']):
            return "48 Port Switches"
            
        # 24-port switches
        if any(x in model for x in ['24p', '24-port', '24port', '24t', '-24']):
            return "24 Port Switches"
    
    return None  # Ignore other device types


def write_inventory_report(device_counts: Dict[str, Dict[str, int]], matched_sites: List[str]) -> None:
    """Write detailed inventory report to a text file.
    
    Args:
        device_counts (Dict[str, Dict[str, int]]): Counts of devices by site and type
        matched_sites (List[str]): List of sites that were matched to CSV
    """
    try:
        with open("dnac_inventory.txt", "w") as f:
            f.write("DNA Center Inventory Report\n")
            f.write("=========================\n\n")
            
            # First list matched sites
            f.write("Matched Sites\n")
            f.write("------------\n")
            for site_name in sorted(matched_sites):
                counts = device_counts[site_name]
                f.write(f"\nSite: {site_name}\n")
                f.write("Device Counts:\n")
                for device_type, count in counts.items():
                    if count > 0:  # Only show device types that were found
                        f.write(f"  {device_type}: {count}\n")
            
            # Then list unmatched sites
            unmatched_sites = set(device_counts.keys()) - set(matched_sites)
            if unmatched_sites:
                f.write("\n\nUnmatched Sites\n")
                f.write("--------------\n")
                for site_name in sorted(unmatched_sites):
                    counts = device_counts[site_name]
                    f.write(f"\nSite: {site_name}\n")
                    f.write("Device Counts:\n")
                    for device_type, count in counts.items():
                        if count > 0:  # Only show device types that were found
                            f.write(f"  {device_type}: {count}\n")
            
            # Add summary
            f.write("\n\nSummary\n")
            f.write("-------\n")
            f.write(f"Total Sites Found: {len(device_counts)}\n")
            f.write(f"Sites Matched to CSV: {len(matched_sites)}\n")
            f.write(f"Sites Not Matched: {len(unmatched_sites)}\n")
            
            # Total device counts across all sites
            total_counts = {
                "Distribution Routers": 0,
                "48 Port Switches": 0,
                "24 Port Switches": 0
            }
            for site_counts in device_counts.values():
                for device_type, count in site_counts.items():
                    total_counts[device_type] += count
            
            f.write("\nTotal Devices Found:\n")
            for device_type, count in total_counts.items():
                if count > 0:  # Only show device types that were found
                    f.write(f"  {device_type}: {count}\n")
        
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

    # Process each device
    device_counts = {}  # Track counts per site
    matched_sites = []  # Track which sites were matched to CSV
    
    for device in devices:
        try:
            # Debug print for device details
            print("\nProcessing device:")
            print(f"Hostname: {device.get('hostname', 'N/A')}")
            print(f"Location: {device.get('locationName', 'N/A')}")
            print(f"Model: {device.get('platformId', 'N/A')}")
            
            # Get site name with defensive programming
            location_name = device.get('locationName')
            hostname = device.get('hostname')
            
            if location_name:
                site_name = location_name.strip()
                print(f"Using location name: {site_name}")
            elif hostname:
                site_name = hostname.strip()
                print(f"Using hostname as fallback: {site_name}")
            else:
                print(f"WARNING: No location or hostname found for device: {device}")
                continue

            category = categorize_device(device)
            if category:  # Only count switches
                if site_name not in device_counts:
                    device_counts[site_name] = {
                        "Distribution Routers": 0,
                        "48 Port Switches": 0,
                        "24 Port Switches": 0
                    }
                device_counts[site_name][category] += 1
                print(f"Found {category} at site '{site_name}': {device.get('platformId', 'Unknown model')}")
        except Exception as e:
            print(f"Error processing device: {e}")
            print("Device data:")
            print(json.dumps(device, indent=2))
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
                            # Increment counts for each switch type
                            for category, count in counts.items():
                                if count > 0:  # Only update if we found switches of this type
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
    write_inventory_report(device_counts, matched_sites)


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
