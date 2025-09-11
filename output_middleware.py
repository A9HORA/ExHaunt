import csv
import json
from pathlib import Path

def write_csv(data: list, filename: str, fieldnames: list):
    """
    Writes data (list of dicts) to a CSV file.
    """
    path = Path(filename)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def write_json(data: list, filename: str):
    """
    Writes data (list of dicts) to a JSON file.
    """
    path = Path(filename)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
