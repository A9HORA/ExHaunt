import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

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

def _fmt_fp(fp_list):
    """Return fingerprint string or explicit message if none matched."""
    if isinstance(fp_list, list) and fp_list:
        return ";".join(fp_list)
    return "no fingerprints matched"

def _tcp_cols(r: dict) -> tuple[str, str]:
    """
    Pick the first probed IP (same ordering as service_provider.ips slice)
    and return (tcp_80, tcp_443). If absent, return empty strings.
    """
    tcp_states = r.get("tcp_states") or {}
    sp = r.get("service_provider") or {}
    ips = sp.get("ips") or []
    if not tcp_states or not ips:
        return ("", "")
    first_ip = ips[0]
    states = tcp_states.get(first_ip) or {}
    return (states.get("tcp_80", "") or "", states.get("tcp_443", "") or "")

def _flatten_row(r: dict) -> dict:
    """Flatten ExHaunt nested result to CSV (+ takeover, confidence & TCP fields)."""
    dp = r.get("dns_provider") or {}
    cls = dp.get("classification") or {}
    dom = r.get("domain_owner") or {}
    sp = r.get("service_provider") or {}
    chain = sp.get("cname_chain") or []
    ipw = sp.get("ip_whois") or {}

    tcp80, tcp443 = _tcp_cols(r)

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
        "service_cname_chain": _join(chain),
        "service_ips": _join(sp.get("ips") or []),
        "service_country": ipw.get("asn_country_code") or "",
        "service_network": ipw.get("network_name") or "",
        "service_asn": ipw.get("asn") or "",
        "service_asn_desc": ipw.get("asn_description") or "",
        "takeover_type": r.get("takeover_type") or "",
        "takeover_confidence": (r.get("takeover_confidence") or ""),
        "http_fp": _fmt_fp(r.get("http_fingerprints") or []),
        "tcp_80": tcp80,
        "tcp_443": tcp443,
    }

# ---------------- JSON compaction helpers ----------------

def _prune_empty(obj):
    """Recursively drop None / empty dicts / empty lists."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            pv = _prune_empty(v)
            if pv is None:
                continue
            if isinstance(pv, (dict, list)) and len(pv) == 0:
                continue
            out[k] = pv
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            pv = _prune_empty(v)
            if pv is None:
                continue
            if isinstance(pv, (dict, list)) and len(pv) == 0:
                continue
            out.append(pv)
        return out
    return obj

def _compact_result(r: dict) -> dict:
    """
    Keep decision-critical fields; drop heavy debug payloads & duplicates.
    NOTE: tcp_states is preserved in compact JSON.
    """
    r2 = deepcopy(r)

    # dns_provider
    dp = r2.get("dns_provider")
    if isinstance(dp, dict):
        dp.pop("dns_error", None)

    # domain_owner
    dom = r2.get("domain_owner")
    if isinstance(dom, dict):
        dom.pop("tls_cert", None)

    # service_provider
    sp = r2.get("service_provider")
    if isinstance(sp, dict):
        ipw = sp.get("ip_whois")
        if isinstance(ipw, dict):
            ipw.pop("raw", None)
            compact_ipw = {
                k: ipw.get(k)
                for k in ("asn", "asn_description", "asn_country_code", "network_name")
                if ipw.get(k) is not None
            }
            sp["ip_whois"] = compact_ipw
        sp.pop("rdap", None)

    # http_probe: keep fingerprints + confidence, drop per_ip blobs
    hp = r2.get("http_probe")
    if isinstance(hp, dict):
        hp.pop("per_ip", None)

    # Preserve tcp_states
    # Duplicates: keep http_probe.fingerprints; drop separate http_fingerprints
    r2.pop("http_fingerprints", None)

    return _prune_empty(r2)

# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ExHaunt 👻 by a9hora — Subdomain Takeover & Ownership Analyzer",
        epilog="""Examples:
  python exhaunt.py --file subs.txt
  python exhaunt.py --subs www.example.com api.example.com
  python exhaunt.py --file subs.txt --threads auto --mode strict --fp-file fingerprints.yaml
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
    parser.add_argument("--color", action="store_true", help="Enable colored live output (vulns/candidates)")

    parser.add_argument("--mode", choices=["strict","loose"], default="strict",
                        help="Detection strictness: 'strict' = hard evidence only, 'loose' = also surface suspicious but unproven cases")
    parser.add_argument("--rdap-mode", choices=["fast","polite"], default="fast",
                        help="RDAP behavior: 'fast' = single try, 'polite' = retries with backoff & Retry-After")
    
    parser.add_argument("--print", dest="print_mode", choices=["short", "summary", "both"], default="both",
                        help="Console verbosity: 'short' (live minimal lines), 'summary' (final detailed recap), or 'both' (default).")

    # HTTP/TLS probing & fingerprints
    parser.add_argument("--http-probe", action="store_true",
                        help="Enable HTTP/TLS probing + fingerprinting (default OFF; auto-enabled if you pass --mode)")
    parser.add_argument("--no-sni", action="store_true",
                        help="Also run HTTPS probe without SNI (context only; does not promote by itself)")
    parser.add_argument("--http-timeout", type=float, default=3.0, help="HTTP connect/read timeout per probe (default: 3.0)")
    parser.add_argument("--http-retries", type=int, default=1, help="HTTP retries on transient errors (default: 1)")
    parser.add_argument("--http-max-ips", type=int, default=2, help="Max IPs to probe per host (default: 2)")
    parser.add_argument("--fp-file", default=os.path.join(os.path.dirname(__file__), "fingerprints.yaml"),
                        help="Fingerprint YAML file (default: ./fingerprints.yaml)")

    # Cloud provider taxonomy (YAML-first)
    parser.add_argument("--providers-file",
                        default=os.path.join(os.path.dirname(__file__), "providers.yaml"),
                        help="Cloud providers YAML (ASNs + regex). Default: ./providers.yaml")
    parser.add_argument("--add-cloud-marker", action="append", default=[],
                        help="Add a regex marker for provider matching (can be used multiple times)")
    parser.add_argument("--cloud-asn", action="append", default=[],
                        help="Add a specific ASN to treat as cloud (e.g., --cloud-asn 15169). Can be repeated.")
    parser.add_argument("--whois-max-ips", type=int, default=1,
                        help="Sample up to N IPs for IPWhois RDAP (default: 1 = first IP only)")

    # Unknown ASN logging
    parser.add_argument("--unknown-cloud-log", default=None,
                        help="Path to log suspicious unknown ASNs (CSV lines). Disabled if not provided.")

    # JSON compaction
    parser.add_argument("--json-compact", action="store_true",
                        help="Write a trimmed JSON (drops heavy blobs, keeps tcp_states)")

    args = parser.parse_args()

    # Let ownership_middleware colorize warnings
    if args.color:
        os.environ["EXHAUNT_COLOR"] = "1"

    if args.color and not args.quiet:
        print("ExHaunt 👻 by a9hora — scanning for haunted subdomains…")

    # threads
    if str(args.threads).lower() == "auto":
        max_workers = min(64, (os.cpu_count() or 4) * 2)
    else:
        try:
            max_workers = int(args.threads)
        except ValueError:
            print("--threads must be an integer or 'auto'", file=sys.stderr); sys.exit(2)

    # inputs
    if args.file:
        subdomains = read_input_file(args.file)
        output_prefix = os.path.splitext(os.path.basename(args.file))[0]
    else:
        subdomains = args.subs
        output_prefix = "console_input"

    if not subdomains:
        print("No subdomains provided.", file=sys.stderr); sys.exit(2)

    # Auto-enable probing when user explicitly sets --mode
    user_specified_mode = any(a == "--mode" for a in sys.argv)
    effective_http_probe = args.http_probe or user_specified_mode

    # middleware
    om = OwnershipMiddleware(
        whois_delay=args.whois_delay,
        mode=args.mode,
        rdap_mode=args.rdap_mode,
        http_probe_enabled=effective_http_probe,
        http_timeout=args.http_timeout,
        http_retries=args.http_retries,
        http_max_ips=args.http_max_ips,
        no_sni=args.no_sni,
        fp_file=args.fp_file,
        providers_file=args.providers_file,
        add_cloud_markers=args.add_cloud_marker or [],
        extra_cloud_asns=[int(x) for x in (args.cloud_asn or []) if str(x).isdigit()],
        unknown_cloud_log=args.unknown_cloud_log,
        whois_max_ips=args.whois_max_ips,
    )

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

            if args.color and args.print_mode in ("short", "both"):
                dp = (res.get("dns_provider") or {})
                cls = (dp.get("classification") or {})
                risk = cls.get("risk", "OK")
                takeover_type = res.get("takeover_type") or ""
                is_loose = (res.get("loose_vulnerable") is True and args.mode == "loose")
                if risk == "VULNERABLE" or is_loose or takeover_type.startswith("A_CLOUD_REUSE"):
                    host = res.get("hostname", "?")
                    reason = cls.get("reason", "")
                    fp = ";".join(res.get("http_fingerprints") or []) or "no fingerprints matched"
                    conf = res.get("takeover_confidence")
                    extra = f" | CONF={conf}" if conf else ""
                    print(Fore.RED + f"[{risk}] {host} :: {reason} | TAKEOVER={takeover_type}{extra} | FP={fp}" + Style.RESET_ALL)

    # JSON
    if args.json_compact:
        compacted = [_compact_result(r) for r in results]
        write_json(compacted, f"{output_prefix}.json")
    else:
        write_json(results, f"{output_prefix}.json")

    # CSV (+ takeover, confidence & TCP fields)
    flat_rows = [_flatten_row(r) for r in results]
    fieldnames = [
        "subdomain","cname","hostname_ips","status","takeover_risk","owner_registrar","owner_org",
        "dns_provider","dns_error","service_cname","service_cname_chain",
        "service_ips","service_country","service_network","service_asn","service_asn_desc",
        "takeover_type","takeover_confidence","http_fp","tcp_80","tcp_443"
    ]
    write_csv(flat_rows, f"{output_prefix}.csv", fieldnames)

    # final summary
    # final summary (compact; no TCP state printed)
    if args.color and args.print_mode in ("summary", "both"):
        for r in results:
            host = r.get("hostname", "?")
            dp = r.get("dns_provider") or {}
            cls = dp.get("classification") or {}
            risk = cls.get("risk", "OK"); reason = cls.get("reason", "")
            ns = (dp.get("ns") or [])[:4]
            owner = (r.get("domain_owner") or {}).get("whois_owner")
            sp = r.get("service_provider") or {}
            cname = sp.get("cname_chain") or []
            ipw = (sp.get("ip_whois") or {})
            asn = ipw.get("asn"); asn_desc = ipw.get("asn_description")
            takeover_type = r.get("takeover_type") or ""
            fp = ";".join(r.get("http_fingerprints") or []) or "no fingerprints matched"
            conf = r.get("takeover_confidence")
    
            if risk == "VULNERABLE": color = Fore.RED
            elif risk in ("BROKEN","ENV_ERROR"): color = Fore.YELLOW
            elif risk == "RETRY": color = Fore.MAGENTA
            else: color = Fore.CYAN
    
            line = f"[{risk}] {host} :: {reason} | TAKEOVER={takeover_type}"
            if conf: line += f" | CONF={conf.upper()}"
            line += f" | NS={ns} | WHOIS_ORG={owner}"
            if cname: line += f" | CNAME→{cname[-1]}"
            if asn or asn_desc: line += f" | ASN={asn} ({asn_desc})"
            if fp: line += f" | FP={fp}"
            print(color + line + Style.RESET_ALL)

if __name__ == "__main__":
    main()