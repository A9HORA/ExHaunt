from pathlib import Path

def read_input_file(file_path: str) -> list:
    """
    Reads subdomains from a text file (one per line).
    Returns a list of subdomains.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    with path.open("r") as f:
        subdomains = [line.strip() for line in f if line.strip()]
    return subdomains
