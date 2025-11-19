import csv
import json

def write_json(data, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def write_csv(rows: list[dict], path: str, fieldnames: list[str]):
    """
    Write CSV with stable field order. Missing keys become empty strings.
    """
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            row = {k: ("" if r.get(k) is None else r.get(k)) for k in fieldnames}
            w.writerow(row)
