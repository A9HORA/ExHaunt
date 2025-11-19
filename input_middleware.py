import os

def read_input_file(path: str) -> list[str]:
    """
    Read subdomains from a file (one per line), stripping comments/empties.
    Returns in file order (stable), de-duplicated.
    """
    if not os.path.isfile(path):
        return []
    seen = set()
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s not in seen:
                out.append(s)
                seen.add(s)
    return out
