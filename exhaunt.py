import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from input_middleware import read_input_file
from output_middleware import write_csv, write_json
from ownership_middleware import OwnershipMiddleware
from progress_middleware import ProgressMiddleware
from colorama import Fore, Style, init

# Windows-friendly colors
init(autoreset=True)

def _bump_nofile_limit():
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            new_soft = min(max(soft, 8192), hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
        except Exception:
            pass

_bump_nofile_limit()

def process_one(hostname: str, om: OwnershipMiddleware) -> dict:
    try:
        return om.analyze(hostname)
    except Exception as e:
        return {"hostname": hostname, "error": str(e)}

def _first(lst):
    return lst[0] if isinstance(lst, list) and lst else None

def _join(lst):
    return ";".join(lst) if isinstance(lst, list) else (lst or "")

def _flatten_row(r: dict) -> dict:
    """Flatten ExHaunt nested result to your legacy CSV schema."""
    dp = r.get("dns_provider") or {}
    cls = dp.get("classification") or {}
    dom = r.get("domain_owner") or {}
    sp = r.get("service_provider") or {}
    chain = sp.get("cname_chain") or []
    ipw = sp.get("ip_whois") or {}

    return {
        "subdomain": r.get("hostname", ""),
        "cname": _first(chain) or "",
        "hostname_ips": _join(r.get("hostname_ips") or []),
        "status": cls.get("reason", ""),
        "takeover_risk": cls.get("risk", ""),
        "owner_registrar": dom.get("whois_registrar") or "",
        "owner_org": dom.get("whois_owner") or "",
        "dns_provider": _join(dp.get("ns") or []),
        "dns_error": dp.get("dns_error") or "",
        "service_cname": (chain[-1] if chain else ""),
        "service_cname_chain": _join(chain),  # NEW: full chain
        "service_ips": _join(sp.get("ips") or []),
        "service_country": ipw.get("asn_country_code") or "",
        "service_network": ipw.get("network_name") or "",
        "service_asn": ipw.get("asn") or "",
        "service_asn_desc": ipw.get("asn_description") or "",
    }

def main():
    parser = argparse.ArgumentParser(
        description="ExHaunt 👻 by a9hora — Subdomain Takeover & Ownership Analyzer",
        epilog="""Examples:
  # From file
  python exhaunt.py --file subs.txt

  # From CLI subdomains
  python exhaunt.py --subs www.example.com api.example.com

  # Custom threads and whois delay
  python exhaunt.py --file subs.txt --threads 30 --whois-delay 2

  # Auto thread mode
  python exhaunt.py --file subs.txt --threads auto

  # Quiet mode (no progress bar)
  python exhaunt.py --file subs.txt --quiet

  # Log progress to file
  python exhaunt.py --file subs.txt --logfile run.log

  # With live colored takeover warnings (only vulnerable ones)
  python exhaunt.py --file subs.txt --color
""",
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to input file with subdomains (one per line)")
    group.add_argument("--subs", nargs="+", help="One or more subdomains passed directly")

    parser.add_argument("--threads", default="10", help="Number of parallel threads (default: 10, or 'auto')")
    parser.add_argument("--whois-delay", type=float, default=1.0, help="Seconds to wait between WHOIS lookups (default: 1.0)")
    parser.add_argument("--quiet", action="store_true", help="Disable progress bar output")
    parser.add_argument("--logfile", default=None, help="Optional log file to write progress updates")
    parser.add_argument("--color", action="store_true", help="Enable colored live output (vulnerable only)")
    parser.add_argument("--mode", choices=["strict","loose"], default="strict",
                        help="Detection strictness: 'strict' = hard evidence only, 'loose' = also haunts suspicious but unproven cases")
    parser.add_argument("--rdap-mode", choices=["fast","polite"], default="fast",
                        help="RDAP behavior: 'fast' = single try, 'polite' = retries with backoff & Retry-After")

    args = parser.parse_args()

    # Optional banner (only with --color and not --quiet)
    if args.color and not args.quiet:
        print("ExHaunt 👻 by a9hora — scanning for haunted subdomains…")

    # threads parse
    if str(args.threads).lower() == "auto":
        max_workers = min(64, (os.cpu_count() or 4) * 2)
    else:
        try:
            max_workers = int(args.threads)
        except ValueError:
            print("--threads must be an integer or 'auto'", file=sys.stderr)
            sys.exit(2)

    # inputs
    if args.file:
        subdomains = read_input_file(args.file)
        output_prefix = os.path.splitext(os.path.basename(args.file))[0]
    else:
        subdomains = args.subs
        output_prefix = "console_input"

    if not subdomains:
        print("No subdomains provided.", file=sys.stderr)
        sys.exit(2)

    # middleware
    om = OwnershipMiddleware(whois_delay=args.whois_delay, mode=args.mode, rdap_mode=args.rdap_mode)

    # run
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(process_one, s, om) for s in subdomains]

        progress = ProgressMiddleware(
            total=len(futs),
            desc="Scanning",
            unit="sub",
            disable=args.quiet,
            log_file=args.logfile,
        )

        for f in progress.wrap_futures(futs):
            res = f.result()
            results.append(res)

            # live vulnerable-only lines
            if args.color:
                dp = (res.get("dns_provider") or {})
                cls = (dp.get("classification") or {})
                is_loose = res.get("loose_vulnerable") is True and args.mode == "loose"
                if cls.get("risk") == "VULNERABLE" or is_loose:
                    host = res.get("hostname", "?")
                    reason = cls.get("reason", "") if cls.get("risk") == "VULNERABLE" else "Suspicious provider suffix (haunted)"
                    print(Fore.RED + f"[VULNERABLE] {host} :: {reason}" + Style.RESET_ALL)

    # JSON stays full-fidelity (nested)
    write_json(results, f"{output_prefix}.json")

    # CSV: flatten to your legacy schema/columns (+ full chain)
    flat_rows = [_flatten_row(r) for r in results]
    fieldnames = [
        "subdomain","cname","hostname_ips","status","takeover_risk","owner_registrar","owner_org",
        "dns_provider","dns_error","service_cname","service_cname_chain",
        "service_ips","service_country","service_network","service_asn","service_asn_desc"
    ]
    write_csv(flat_rows, f"{output_prefix}.csv", fieldnames)

    # final summary
    for r in results:
        host = r.get("hostname", "?")
        dp = r.get("dns_provider") or {}
        cls = dp.get("classification") or {}
        risk = cls.get("risk", "OK")
        reason = cls.get("reason", "")
        ns = (dp.get("ns") or [])[:4]
        owner = (r.get("domain_owner") or {}).get("whois_owner")
        sp = r.get("service_provider") or {}
        cname = sp.get("cname_chain") or []
        ipw = (sp.get("ip_whois") or {})
        asn = ipw.get("asn")
        asn_desc = ipw.get("asn_description")

        if risk == "VULNERABLE":
            color = Fore.RED
        elif risk in ("BROKEN","ENV_ERROR"):
            color = Fore.YELLOW
        elif risk == "RETRY":
            color = Fore.MAGENTA
        else:
            color = Fore.CYAN

        line = f"[{risk}] {host} :: {reason} | NS={ns} | WHOIS_ORG={owner}"
        if cname:
            line += f" | CNAME→{cname[-1]}"
        if asn or asn_desc:
            line += f" | ASN={asn} ({asn_desc})"
        print(color + line + Style.RESET_ALL)

if __name__ == "__main__":
    main()