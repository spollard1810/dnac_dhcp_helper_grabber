## Class to output response to csv

import csv
from typing import Dict, Any, List
from datetime import datetime

class OutputHelper:
    def __init__(self, response: Dict[str, Any]):
        self.response = response
        self.data = self._extract_data()

    def _extract_data(self) -> List[Dict[str, Any]]:
        """Extract the actual data from the DNAC response."""
        if isinstance(self.response, dict) and 'response' in self.response:
            return self.response['response'] if isinstance(self.response['response'], list) else [self.response['response']]
        return [self.response] if isinstance(self.response, dict) else self.response

    def to_csv(self, filename: str = None) -> str:
        """Convert response data to CSV.
        
        Args:
            filename (str, optional): Output filename. If not provided, generates a timestamped filename.
            
        Returns:
            str: Path to the created CSV file
        """
        if not self.data:
            raise ValueError("No data to convert to CSV")

        # Generate filename if not provided
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dnac_output_{timestamp}.csv"

        # Get all unique keys from all items
        headers = set()
        for item in self.data:
            headers.update(item.keys())
        headers = sorted(list(headers))

        # Write to CSV
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(self.data)

        return filename