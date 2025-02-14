#!/usr/bin/env python3

from api import client
import json
from typing import Dict, Any, List, Tuple
import logging
import csv
from difflib import SequenceMatcher

# Set up debug logging
logging.basicConfig(level=logging.DEBUG)
requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


def find_matches(target: str, candidates: List[str], threshold: float = 0.9) -> List[str]:
    """Find all matches in candidates that exceed the similarity threshold.
    Each candidate may contain multiple site names separated by ' / '.
    
    Args:
        target (str): String to match
        candidates (List[str]): List of possible matches (may contain multiple names per entry)
        threshold (float): Minimum similarity ratio to consider a match
        
    Returns:
        List[str]: List of matches that exceed the threshold
    """
    matches = []
    for candidate in candidates:
        # Split candidate into individual site names
        site_names = [name.strip() for name in candidate.split('/')]
        
        # Check each individual site name
        for site_name in site_names:
            if not site_name:  # Skip empty strings
                continue
            ratio = SequenceMatcher(None, target.lower(), site_name.lower()).ratio()
            if ratio >= threshold:
                matches.append(candidate)  # Add the full abbrev string as a match
                break  # Move to next candidate once we find a match
    return list(set(matches))  # Remove any duplicates


def categorize_device(device: Dict[str, Any]) -> str:
    """Get device model information.
    
    Args:
        device (Dict[str, Any]): Device information from DNA Center
        
    Returns:
        str: Device model or None if not a switch or if it's an ISR
    """
    family = device.get('family', '').lower()
    series = device.get('series', '').lower()
    platform_id = device.get('platformId', '')
    
    # Skip ISRs and non-switches
    if 'isr' in platform_id.lower() or 'isr' in series.lower():
        return None
    
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


def update_inventory(csv_data: List[Dict[str, str]], devices: List[Dict[str, Any]]) -> Tuple[List[Dict[str, str]], Dict[str, List[str]]]:
    """Update inventory counts in CSV data using abbrev column for matching.
    
    Args:
        csv_data (List[Dict[str, str]]): Existing CSV data
        devices (List[Dict[str, Any]]): Device list from DNA Center
        
    Returns:
        Tuple[List[Dict[str, str]], Dict[str, List[str]]]: Updated CSV data and unmatched sites
    """
    # Add 'matched' column if it doesn't exist
    if 'matched' not in csv_data[0]:
        for row in csv_data:
            row['matched'] = 'N'
    
    # Process devices and group by site
    device_counts = {}
    unmatched_sites = {}
    
    for device in devices:
        try:
            hostname = device.get('hostname', '')
            if not hostname:
                continue
            
            site = get_site_from_hostname(hostname)
            model = categorize_device(device)
            
            if model:  # Only count switches
                if site not in device_counts:
                    device_counts[site] = {}
                if model not in device_counts[site]:
                    device_counts[site][model] = 0
                device_counts[site][model] += 1
        except Exception as e:
            print(f"Error processing device {hostname}: {e}")
            continue
    
    # Get list of abbreviations
    abbrevs = [row['abbrev'].strip() for row in csv_data]
    
    # Update CSV with counts
    for site, counts in device_counts.items():
        # Find potential matches with higher threshold
        matches = find_matches(site, abbrevs)
        
        if len(matches) == 0:
            # No match found
            unmatched_sites[site] = ["No match found"]
            continue
        elif len(matches) > 1:
            # Multiple potential matches
            unmatched_sites[site] = [f"Multiple matches: {', '.join(matches)}"]
            continue
        
        # Exactly one match found
        match = matches[0]
        for row in csv_data:
            if row['abbrev'].strip() == match:
                try:
                    # Map models to CSV categories
                    csv_counts = {
                        "Distribution Routers": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['9300', '9500'])),
                        "48 Port Switches": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['48p', '48-port', '48port', '48t', '-48'])),
                        "24 Port Switches": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['24p', '24-port', '24port', '24t', '-24'])),
                        "12 Port Switches": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['12p', '12-port', '12port', 'c9200cx-12'])),
                        "9410 / Chassis": sum(count for model, count in counts.items() if any(x in model.lower() for x in ['9410', '9407', '9606', 'c9407', 'c9606']))
                    }
                    
                    # Update CSV with categorized counts
                    for category, count in csv_counts.items():
                        if count > 0:
                            current_count = int(row.get(category, "0") or "0")
                            row[category] = str(current_count + count)
                    
                    row['matched'] = 'Y'
                    print(f"Matched site '{site}' to '{match}' and updated counts")
                except ValueError as e:
                    print(f"Error updating counts for {match}: {e}")
                break
    
    return csv_data, unmatched_sites


def write_inventory_report(devices: List[Dict[str, Any]], unmatched_sites: Dict[str, List[str]]) -> None:
    """Write detailed inventory report to a text file.
    
    Args:
        devices (List[Dict[str, Any]]): List of devices from DNA Center
        unmatched_sites (Dict[str, List[str]]): Sites that couldn't be matched
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
                if site in unmatched_sites:
                    f.write(f"WARNING: {unmatched_sites[site][0]}\n")
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
            
            # Add unmatched sites summary
            if unmatched_sites:
                f.write("\nUnmatched Sites:\n")
                f.write("-" * 15 + "\n")
                for site, reasons in sorted(unmatched_sites.items()):
                    f.write(f"  {site}: {reasons[0]}\n")
        
        print(f"\nDetailed inventory report written to dnac_inventory.txt")
    except Exception as e:
        print(f"Error writing inventory report: {e}")


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
        
        # Update inventory and get unmatched sites
        updated_csv, unmatched_sites = update_inventory(csv_data, devices)
        
        # Generate inventory report
        write_inventory_report(devices, unmatched_sites)
        
        # Write updated data back to CSV
        with open("input.csv", "w", newline="") as csvfile:
            fieldnames = updated_csv[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(updated_csv)
        
        print("\nSuccessfully updated input.csv")
        client.close()

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
