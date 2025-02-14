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
    platform = device.get('platform', '')  # Use platform instead of platformId
    
    # Only process switches
    if 'switch' in family or 'catalyst' in series:
        return platform
    
    return None


def write_inventory_report(device_counts: Dict[str, Dict[str, int]], matched_sites: List[str]) -> None:
    """Write detailed inventory report to a text file.
    
    Args:
        device_counts (Dict[str, Dict[str, int]]): Counts of devices by site and model
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
                if any(count > 0 for count in counts.values()):  # Only show sites with devices
                    f.write(f"\nSite: {site_name}\n")
                    f.write("Device Models:\n")
                    for model, count in sorted(counts.items()):
                        if count > 0:  # Only show models that were found
                            f.write(f"  {model}: {count}\n")
            
            # Then list unmatched sites
            unmatched_sites = set(device_counts.keys()) - set(matched_sites)
            if unmatched_sites:
                f.write("\n\nUnmatched Sites\n")
                f.write("--------------\n")
                for site_name in sorted(unmatched_sites):
                    counts = device_counts[site_name]
                    if any(count > 0 for count in counts.values()):  # Only show sites with devices
                        f.write(f"\nSite: {site_name}\n")
                        f.write("Device Models:\n")
                        for model, count in sorted(counts.items()):
                            if count > 0:  # Only show models that were found
                                f.write(f"  {model}: {count}\n")
            
            # Add summary
            f.write("\n\nSummary\n")
            f.write("-------\n")
            f.write(f"Total Sites Found: {len(device_counts)}\n")
            f.write(f"Sites Matched to CSV: {len(matched_sites)}\n")
            f.write(f"Sites Not Matched: {len(unmatched_sites)}\n")
            
            # Total device counts across all sites by model
            total_counts = {}
            for site_counts in device_counts.values():
                for model, count in site_counts.items():
                    if model not in total_counts:
                        total_counts[model] = 0
                    total_counts[model] += count
            
            if total_counts:
                f.write("\nTotal Devices by Model:\n")
                for model, count in sorted(total_counts.items()):
                    if count > 0:  # Only show models that were found
                        f.write(f"  {model}: {count}\n")
        
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
            location = device.get('location')
            if not location:
                continue

            site_name = location.strip()
            model = categorize_device(device)
            if model:  # Only count switches
                if site_name not in device_counts:
                    device_counts[site_name] = {}
                if model not in device_counts[site_name]:
                    device_counts[site_name][model] = 0
                device_counts[site_name][model] += 1
                all_models.add(model)
        except Exception as e:
            print(f"Error processing device: {e}")
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
