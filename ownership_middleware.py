import os
import re
import sys
import socket
import ssl
import time
import threading
from enum import Enum
from typing import Dict, List, Optional, Tuple
from base64 import b64encode

import dns.exception
import dns.resolver
import tldextract
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

try:
    import whois
except Exception:
    whois = None

try:
    from ipwhois import IPWhois
except Exception:
    IPWhois = None

try:
    import yaml  # for fingerprints/providers
except Exception:
    yaml = None

# ---------- Color-aware warning helper ----------
def _warn(msg: str):
    """Print a warning; colorized if EXHAUNT_COLOR=1 and stderr is a TTY."""
    use_color = os.environ.get("EXHAUNT_COLOR") == "1" and sys.stderr.isatty()
    if use_color:
        sys.stderr.write("\x1b[33m[WARNING]\x1b[0m " + msg + "\n")
    else:
        sys.stderr.write("[WARNING] " + msg + "\n")
    try:
        sys.stderr.flush()
    except Exception:
        pass
# ------------------------------------------------

# =============================
# Risk classification
# =============================
class Risk(Enum):
    OK = "OK"
    BROKEN = "BROKEN"
    VULNERABLE = "VULNERABLE"
    RETRY = "RETRY"
    ENV_ERROR = "ENV_ERROR"

def classify(risk: Risk, reason: str, evidence: Optional[dict] = None, confidence: str = "LOW") -> dict:
    return {
        "risk": risk.value,
        "reason": reason,
        "confidence": confidence,
        "evidence": evidence or {},
    }

# =============================
# Global concurrency guard
# =============================
_NET_SEM = threading.BoundedSemaphore(value=int(os.environ.get("NET_CONCURRENCY", "128")))

# =============================
# DNS resolver helpers (system-first, public fallback)
# =============================
def _make_resolver(timeout: float = 3.0, lifetime: float = 5.0, nameservers: Optional[List[str]] = None) -> dns.resolver.Resolver:
    """
    Build a resolver. If nameservers is None -> use system resolver; otherwise set explicit servers.
    Timeouts/lifetime can be overridden by env: DNS_TIMEOUT / DNS_LIFETIME
    """
    r = dns.resolver.Resolver(configure=(nameservers is None))
    if nameservers:
        r.nameservers = nameservers
    r.timeout = float(os.environ.get("DNS_TIMEOUT", timeout))
    r.lifetime = float(os.environ.get("DNS_LIFETIME", lifetime))
    return r

_RESOLVER_POOLS: List[List[str]] = [
    ["8.8.8.8", "8.8.4.4"],           # Google
    ["1.1.1.1", "1.0.0.1"],           # Cloudflare
    ["9.9.9.9", "149.112.112.112"],   # Quad9
]

def _resolve_with_multi_fallback(name: str, rtype: str, attempts: int = 2, raise_on_no_answer: bool = False):
    """
    Resolution strategy:
      1) Try system resolver once.
      2) Fall back across public resolver pools, light retries per pool.
    """
    last_exc = None
    # System resolver first
    try:
        with _NET_SEM:
            return _make_resolver().resolve(name, rtype, raise_on_no_answer=raise_on_no_answer)
    except Exception as e:
        last_exc = e
    # Public pools
    for pool in _RESOLVER_POOLS:
        for _ in range(max(1, int(attempts))):
            try:
                with _NET_SEM:
                    return _make_resolver(nameservers=pool).resolve(name, rtype, raise_on_no_answer=raise_on_no_answer)
            except Exception as e:
                last_exc = e
                continue
    if last_exc:
        raise last_exc
    raise dns.exception.DNSException("Resolution failed without specific exception")

def _registrable_domain(host: str) -> str:
    ext = tldextract.extract(host or "")
    if not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"

# =============================
# IPWhois cache
# =============================
_IPWHOIS_CACHE: dict = {}
_IPWHOIS_TTL_SEC: int = 4 * 60 * 60  # 4 hours

def _ipwhois_lookup(ip: str) -> Optional[dict]:
    now = time.time()
    cached = _IPWHOIS_CACHE.get(ip)
    if cached and (now - cached["ts"] < _IPWHOIS_TTL_SEC):
        return cached["data"]
    if IPWhois is None:
        return None
    try:
        with _NET_SEM:
            data = IPWhois(ip).lookup_rdap(depth=1)
        _IPWHOIS_CACHE[ip] = {"ts": now, "data": data}
        return data
    except Exception:
        return None

# =============================
# TLS certificate org extractor
# =============================
def _get_cert_org(hostname: str, port: int = 443, timeout: float = 5.0) -> Optional[dict]:
    try:
        ctx = ssl.create_default_context()
        with _NET_SEM:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        return {"subject": subject, "issuer": issuer}
    except Exception:
        return None

# =============================
# CNAME chain / IPs
# =============================
def _resolve_cname_chain(hostname: str, max_hops: int = 10) -> List[str]:
    chain: List[str] = []
    current = hostname.rstrip(".")
    for _ in range(max_hops):
        try:
            ans = _resolve_with_multi_fallback(current, "CNAME", attempts=2, raise_on_no_answer=False)
            if not ans or not getattr(ans, "rrset", None):
                break
            target = str(ans[0].target).rstrip(".")
            chain.append(target)
            current = target
        except Exception:
            break
    return chain

def _resolve_ips(name: str) -> List[str]:
    ips: List[str] = []
    try:
        ans = _resolve_with_multi_fallback(name, "A", attempts=2, raise_on_no_answer=False)
        if ans and getattr(ans, "rrset", None):
            ips.extend([r.address for r in ans])
    except Exception:
        pass
    try:
        ans6 = _resolve_with_multi_fallback(name, "AAAA", attempts=2, raise_on_no_answer=False)
        if ans6 and getattr(ans6, "rrset", None):
            ips.extend([r.address for r in ans6])
    except Exception:
        pass
    return ips

# =============================
# RDAP helpers (+ 4h cache)
# =============================
_RDAP_BOOTSTRAP_URL = os.environ.get("RDAP_BOOTSTRAP_URL", "https://data.iana.org/rdap/dns.json")
_RDAP_HTTP_TIMEOUT = float(os.environ.get("RDAP_TIMEOUT", "5.0"))

from functools import lru_cache

@lru_cache(maxsize=1)
def _load_rdap_bootstrap() -> dict:
    try:
        with _NET_SEM:
            r = requests.get(_RDAP_BOOTSTRAP_URL, timeout=_RDAP_HTTP_TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {"services": []}

def _rdap_base_urls_for_suffix(suffix: str) -> list:
    data = _load_rdap_bootstrap()
    for service in data.get("services", []):
        tlds, urls = service
        if suffix.lower() in [t.lower() for t in tlds]:
            return urls
    return []

_RDAP_CACHE: dict = {}
_RDAP_TTL_SEC: int = int(os.environ.get("RDAP_TTL_SEC", str(4 * 60 * 60)))  # 4 hours default

def _rdap_cache_get(key: str):
    rec = _RDAP_CACHE.get(key)
    if not rec:
        return None
    if (time.time() - rec["ts"]) > _RDAP_TTL_SEC:
        _RDAP_CACHE.pop(key, None)
        return None
    return rec["data"]

def _rdap_cache_put(key: str, data: dict):
    _RDAP_CACHE[key] = {"ts": time.time(), "data": data}

def _rdap_query_domain(domain: str, mode: str = "fast") -> dict:
    cache_key = f"{domain.lower()}|{mode}"
    cached = _rdap_cache_get(cache_key)
    if cached is not None:
        return cached

    ext = tldextract.extract(domain)
    suffix = ext.suffix
    if not suffix:
        data = {"error": "no suffix"}
        _rdap_cache_put(cache_key, data)
        return data
    urls = _rdap_base_urls_for_suffix(suffix)
    if not urls:
        data = {"error": f"no rdap urls for suffix {suffix}"}
        _rdap_cache_put(cache_key, data)
        return data

    for base in urls:
        base = base.rstrip("/")
        url = f"{base}/domain/{domain}"
        attempts = 1 if mode == "fast" else 4
        backoff = 0.5
        for _ in range(attempts):
            try:
                with _NET_SEM:
                    resp = requests.get(url, timeout=_RDAP_HTTP_TIMEOUT, headers={"Accept": "application/rdap+json, application/json"})
                if resp.status_code == 404:
                    data = {"found": False, "status_code": 404, "server": base}
                    _rdap_cache_put(cache_key, data)
                    return data
                if resp.ok:
                    js = resp.json()
                    statuses = js.get("status") or []
                    data = {"found": True, "ldhName": js.get("ldhName"), "handle": js.get("handle"), "status": statuses, "server": base}
                    _rdap_cache_put(cache_key, data)
                    return data
                if resp.status_code in (429, 502, 503, 504) and mode == "polite":
                    ra = resp.headers.get("Retry-After")
                    delay = float(ra) if (ra and ra.isdigit()) else backoff
                    time.sleep(delay)
                    backoff = min(backoff * 2.0, 8.0)
                    continue
                data = {"found": None, "status_code": resp.status_code, "server": base}
                _rdap_cache_put(cache_key, data)
                return data
            except requests.RequestException as e:
                if mode == "polite":
                    time.sleep(backoff)
                    backoff = min(backoff * 2.0, 8.0)
                    continue
                data = {"error": str(e)}
                _rdap_cache_put(cache_key, data)
                return data

    data = {"error": "rdap query failed"}
    _rdap_cache_put(cache_key, data)
    return data

# =============================
# Provider suffix heuristics (existing)
# =============================
PROVIDER_SUFFIXES = [
    ".github.io", ".githubusercontent.com", ".herokuapp.com", ".netlify.app",
    ".vercel.app", ".cloudfront.net", ".s3.amazonaws.com", ".s3-website", ".azurewebsites.net",
    ".trafficmanager.net", ".blob.core.windows.net", ".storage.googleapis.com"
]

# =============================
# Provider taxonomy (ASNs + regex) — YAML-first with warning fallback
# =============================
def _load_providers(providers_path: Optional[str]) -> dict:
    """
    providers.yaml (authoritative):
      asns: [15169, 16509, ...]         # integers
      patterns:                         # regex strings (case-insensitive)
        - "google|google[-\\s]?cloud|gcp"
        - "amazon|aws|amazon[-\\s]?technologies"
        - ...
    """
    minimal_fallback = {
        "asns": [15169, 16509, 8075, 13335],  # Google, Amazon, Microsoft, Cloudflare
        "patterns": [r"google|gcp", r"amazon|aws", r"microsoft|azure", r"cloudflare"]
    }

    env_path = os.environ.get("EXHAUNT_PROVIDERS_FILE")
    candidates = [providers_path, env_path]

    for p in [x for x in candidates if x]:
        if yaml is None:
            _warn("PyYAML not installed; falling back to minimal provider list.")
            return minimal_fallback
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                asns = [int(a) for a in (data.get("asns") or []) if str(a).isdigit()]
                pats = [str(x) for x in (data.get("patterns") or []) if isinstance(x, (str, bytes))]
                if asns or pats:
                    return {"asns": asns, "patterns": pats}
                _warn(f"{p} is empty; falling back to minimal provider list.")
                return minimal_fallback
            except Exception as e:
                _warn(f"Failed to read providers file {p}: {e}; falling back to minimal provider list.")
                return minimal_fallback
        else:
            _warn(f"Providers file not found at {p}; will try defaults.")

    default_path = os.path.join(os.path.dirname(__file__), "providers.yaml")
    if yaml is not None and os.path.isfile(default_path):
        try:
            with open(default_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            asns = [int(a) for a in (data.get("asns") or []) if str(a).isdigit()]
            pats = [str(x) for x in (data.get("patterns") or []) if isinstance(x, (str, bytes))]
            if asns or pats:
                return {"asns": asns, "patterns": pats}
            _warn("providers.yaml is empty; using minimal provider list.")
            return minimal_fallback
        except Exception as e:
            _warn(f"Failed to read default providers.yaml: {e}; using minimal provider list.")
            return minimal_fallback

    _warn("providers.yaml not found; using minimal provider list. Coverage may be incomplete.")
    return minimal_fallback

def _normalize_str(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _is_cloud_provider(ipwhois_obj: Optional[dict], providers_cfg: dict) -> bool:
    if not ipwhois_obj:
        return False
    try:
        asn = ipwhois_obj.get("asn")
        asn_int = int(asn) if asn and str(asn).isdigit() else None
    except Exception:
        asn_int = None

    if asn_int and asn_int in set(providers_cfg.get("asns", [])):
        return True

    patt = "|".join(providers_cfg.get("patterns", [])) or ""
    if not patt:
        return False
    rx = re.compile(patt, re.I)

    asn_desc = _normalize_str(ipwhois_obj.get("asn_description"))
    net_name = _normalize_str((ipwhois_obj.get("network") or {}).get("name"))
    org_name = ""
    try:
        objects = ipwhois_obj.get("objects") or {}
        parts = []
        for o in objects.values():
            v = o.get("contact", {})
            parts.append(_normalize_str(v.get("name")))
            parts.append(_normalize_str(v.get("organization")))
        org_name = " ".join([p for p in parts if p])
    except Exception:
        org_name = ""

    text = " | ".join([asn_desc, net_name, org_name])
    return bool(rx.search(text))

_GENERIC_CLOUDY_RX = re.compile(
    r"\b(cloud|hosting|datacenter|data\s*center|edge|cdn|compute|virtual|vps|infra|infrastructure)\b",
    re.I
)

def _looks_cloudy_but_unknown(ipwhois_obj: Optional[dict], http_probe: Optional[dict]) -> bool:
    if not ipwhois_obj:
        return False
    fields = [
        _normalize_str(ipwhois_obj.get("asn_description")),
        _normalize_str((ipwhois_obj.get("network") or {}).get("name")),
    ]
    try:
        objects = ipwhois_obj.get("objects") or {}
        for o in objects.values():
            v = o.get("contact", {})
            fields.append(_normalize_str(v.get("name")))
            fields.append(_normalize_str(v.get("organization")))
    except Exception:
        pass
    if any(_GENERIC_CLOUDY_RX.search(x or "") for x in fields):
        return True
    if http_probe and isinstance(http_probe.get("per_ip"), dict):
        for _, blobs in http_probe["per_ip"].items():
            for key in ("http", "https"):
                pkt = blobs.get(key) or {}
                st = pkt.get("status")
                if st in (400, 404, 410, 421, 425, 431, 451, 500, 502, 503, 504):
                    return True
    return False

# =============================
# HTTP/TLS probing + fingerprints
# =============================
def _http_request_raw(ip: str, host: str, port: int, use_tls: bool, use_sni: bool, timeout: float) -> Tuple[Optional[int], Dict[str, str], bytes, Optional[dict]]:
    sock = None
    tls = None
    data = b""
    headers: Dict[str, str] = {}
    try:
        with _NET_SEM:
            sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            server_hostname = host if use_sni else None
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                try:
                    der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der, default_backend())
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    matches = host.lower() in subject.lower()
                    tls = {"subject": subject, "issuer": issuer, "matches_host": matches}
                except Exception:
                    tls = None
                req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ExHaunt/1\r\nConnection: close\r\n\r\n".encode()
                ssock.sendall(req)
                ssock.settimeout(timeout)
                chunk = ssock.recv(8192); data += chunk
                while chunk:
                    if len(data) > 4096: break
                    chunk = ssock.recv(4096); data += chunk
        else:
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ExHaunt/1\r\nConnection: close\r\n\r\n".encode()
            sock.sendall(req); sock.settimeout(timeout)
            chunk = sock.recv(8192); data += chunk
            while chunk:
                if len(data) > 4096: break
                chunk = sock.recv(4096); data += chunk
    except Exception:
        return (None, {}, b"", tls)
    finally:
        try:
            if sock: sock.close()
        except Exception:
            pass

    try:
        head, _, body = data.partition(b"\r\n\r\n")
        status_line, *hdr_lines = head.split(b"\r\n")
        status = None
        if status_line.startswith(b"HTTP/"):
            parts = status_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        for h in hdr_lines:
            if b":" in h:
                k, v = h.split(b":", 1)
                headers[k.decode(errors="ignore").strip().lower()] = v.decode(errors="ignore").strip()
        return (status, headers, body[:2048], tls)
    except Exception:
        return (None, {}, b"", tls)

def _load_fingerprints(fp_path: Optional[str]) -> List[dict]:
    if not fp_path or not os.path.isfile(fp_path) or yaml is None:
        return []
    try:
        with open(fp_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _match_fingerprints(status: Optional[int], headers: Dict[str, str], body: bytes, tls: Optional[dict], fps: List[dict]) -> Tuple[List[str], str]:
    names = []
    conf = "none"
    text = body.decode(errors="ignore")
    rank = {"none": 0, "weak": 1, "medium": 2, "strong": 3}
    for rule in fps:
        name = rule.get("name")
        exp_status = rule.get("status")
        hdrs = rule.get("header") or []
        bodys = rule.get("body") or []
        tls_sub = rule.get("tls_subject")
        tls_iss = rule.get("tls_issuer")
        level = (rule.get("confidence") or "weak").lower()

        ok = True
        if exp_status:
            exp_list = exp_status if isinstance(exp_status, list) else [exp_status]
            if status is None or not any(re.fullmatch(str(x), str(status)) for x in exp_list):
                ok = False
        for h in hdrs:
            if ":" not in h: ok = False; break
            k, rx = h.split(":", 1)
            got = headers.get(k.strip().lower())
            if got is None or re.search(rx.strip(), got, re.I) is None:
                ok = False; break
        for rx in bodys:
            if re.search(rx, text, re.I) is None:
                ok = False; break
        if (tls_sub or tls_iss):
            if not tls: ok = False
            else:
                if tls_sub and re.search(tls_sub, tls.get("subject",""), re.I) is None: ok = False
                if tls_iss and re.search(tls_iss, tls.get("issuer",""), re.I) is None: ok = False

        if ok:
            names.append(name or "unnamed")
            conf = max(conf, level, key=lambda c: rank[c])
    return names, conf

def _probe_http_suite(hostname: str, ips: List[str], timeout: float, no_sni: bool, fps: List[dict]) -> dict:
    if not ips:
        return {}
    results = {}
    matched: List[str] = []
    best_conf = "none"
    rank = {"none": 0, "weak": 1, "medium": 2, "strong": 3}

    for ip in ips:
        st, hdrs, body, _ = _http_request_raw(ip, hostname, 80, use_tls=False, use_sni=False, timeout=timeout)
        if st is not None or hdrs or body:
            names, conf = _match_fingerprints(st, hdrs, body, None, fps)
            matched.extend(names); best_conf = max(best_conf, conf, key=lambda c: rank[c])
            results.setdefault(ip, {})["http"] = {"status": st, "headers": hdrs, "body_prefix_b64": b64encode(body).decode()}
        st2, hdrs2, body2, tls2 = _http_request_raw(ip, hostname, 443, use_tls=True, use_sni=True, timeout=timeout)
        if st2 is not None or hdrs2 or body2 or tls2:
            names2, conf2 = _match_fingerprints(st2, hdrs2, body2, tls2, fps)
            matched.extend(names2); best_conf = max(best_conf, conf2, key=lambda c: rank[c])
            results.setdefault(ip, {})["https"] = {"status": st2, "headers": hdrs2, "body_prefix_b64": b64encode(body2).decode()}
            results[ip]["tls"] = tls2 or {}
        if no_sni:
            st3, hdrs3, body3, tls3 = _http_request_raw(ip, hostname, 443, use_tls=True, use_sni=False, timeout=timeout)
            results.setdefault(ip, {})["https_no_sni"] = {"status": st3, "headers": hdrs3, "body_prefix_b64": b64encode(body3 or b"").decode()}
            if tls3: results[ip]["tls_no_sni"] = tls3

    return {"per_ip": results, "fingerprints": sorted(set(matched)), "confidence": best_conf}

# =============================
# TCP port state helpers (for CSV/JSON, silent on console)
# =============================
def _tcp_port_state(ip: str, port: int, timeout: float) -> str:
    try:
        with _NET_SEM:
            sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            sock.close()
        except Exception:
            pass
        return "open"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "error"
    except Exception:
        return "error"

def _tcp_states_for_ips(ips: List[str], max_ips: int, timeout: float) -> Dict[str, Dict[str, str]]:
    states: Dict[str, Dict[str, str]] = {}
    for ip in (ips or [])[: max(1, int(max_ips))]:
        states[ip] = {
            "tcp_80": _tcp_port_state(ip, 80, timeout),
            "tcp_443": _tcp_port_state(ip, 443, timeout),
        }
    return states

# =============================
# Takeover confidence grading
# =============================
def _grade_takeover_confidence(takeover_type: str,
                               http_probe: Optional[dict],
                               tcp_states: Optional[dict],
                               mode: str) -> str:
    """
    Map signals -> takeover_confidence: none|low|medium|high
    """
    if not takeover_type or takeover_type == "UNKNOWN":
        return "none"

    def any_port_open(states: Optional[dict]) -> bool:
        if not isinstance(states, dict):
            return False
        for s in states.values():
            if not isinstance(s, dict):
                continue
            if s.get("tcp_80") == "open" or s.get("tcp_443") == "open":
                return True
        return False

    hp_conf = (http_probe or {}).get("confidence", "none") or "none"
    is_candidate = takeover_type == "A_CLOUD_REUSE_CANDIDATE"
    is_confirmed = takeover_type == "A_CLOUD_REUSE_CONFIRMED"

    if is_confirmed:
        if hp_conf == "strong":
            return "high"
        if hp_conf in ("medium", "weak"):
            return "medium"
        return "medium"

    if is_candidate:
        if hp_conf in ("medium", "strong"):
            return "medium"
        if hp_conf == "weak" and mode == "loose":
            return "medium"
        if any_port_open(tcp_states):
            return "medium"
        return "low"

    return "none"

# =============================
# Ownership Middleware
# =============================
class OwnershipMiddleware:
    def __init__(
        self,
        whois_delay: float = 1.0,
        mode: str = "strict",
        rdap_mode: str = "fast",
        # HTTP/TLS probe & fingerprints
        http_probe_enabled: bool = False,
        http_timeout: float = 3.0,
        http_retries: int = 1,
        http_max_ips: int = 2,
        no_sni: bool = False,
        fp_file: Optional[str] = None,
        # Provider taxonomy
        providers_file: Optional[str] = None,
        add_cloud_markers: Optional[List[str]] = None,
        extra_cloud_asns: Optional[List[int]] = None,
        # Unknown ASN logging
        unknown_cloud_log: Optional[str] = None,
        # RDAP/WHOIS sampling control for IP whois (propagated from exhaunt.py; backward compatible)
        whois_max_ips: int = 1,
    ):
        self.whois_delay = whois_delay
        self.mode = mode
        self.rdap_mode = rdap_mode
        self.http_probe_enabled = http_probe_enabled
        self.http_timeout = http_timeout
        self.http_retries = http_retries
        self.http_max_ips = max(1, int(http_max_ips))
        self.no_sni = no_sni
        self._fps = _load_fingerprints(fp_file)
        self._providers_cfg = _load_providers(providers_file)
        if add_cloud_markers:
            self._providers_cfg["patterns"] = list(set(self._providers_cfg["patterns"] + add_cloud_markers))
        if extra_cloud_asns:
            base = set(self._providers_cfg["asns"])
            base.update([int(a) for a in extra_cloud_asns if str(a).isdigit()])
            self._providers_cfg["asns"] = sorted(base)

        self._unknown_log_path = unknown_cloud_log or os.environ.get("EXHAUNT_UNKNOWN_ASN_LOG")  # None means disabled
        self._unknown_log_lock = threading.Lock()
        self._unknown_seen: set = set()

        self._whois_lock = threading.Lock()
        self._whois_last = 0.0

        # how many IPs to sample for IPWhois (first N)
        self._whois_max_ips = max(1, int(whois_max_ips))

    # DNS provider (unchanged except resolver fallback)
    def get_dns_provider(self, domain: str) -> Dict:
        base = _registrable_domain(domain)
        result = {"ns": [], "dns_error": None, "classification": classify(Risk.OK, "NS present", {})}
        try:
            try:
                ans = _resolve_with_multi_fallback(base, "NS", attempts=2, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                msg = f"The DNS query name does not exist: {base}."
                rd = _rdap_query_domain(base, mode=getattr(self, "rdap_mode", "fast"))
                evidence = {"domain": base, "rdap": rd}
                conf = "HIGH" if isinstance(rd, dict) and rd.get("found") is False else "MEDIUM"
                result["dns_error"] = f"DNS provider lookup failed: {msg}"
                result["classification"] = classify(Risk.VULNERABLE, msg, evidence, confidence=conf)
                return result
            except dns.resolver.NoNameservers as e:
                msg = f"SERVFAIL/NoNameservers for {base} NS: {e}"
                result["dns_error"] = f"DNS provider lookup failed: {msg}"
                result["classification"] = classify(Risk.BROKEN, "SERVFAIL (broken delegation)", {"domain": base, "error": str(e)})
                return result

            if not ans or not getattr(ans, "rrset", None):
                result["dns_error"] = f"DNS provider lookup failed: No NS answer"
                if self.mode == "loose":
                    result["classification"] = classify(Risk.VULNERABLE, "Empty NS answer (loose mode)", {"domain": base}, confidence="LOW")
                else:
                    result["classification"] = classify(Risk.BROKEN, "Empty NS answer (delegation exists)", {"domain": base})
                return result

            ns_hosts = [str(r.target).rstrip(".") for r in ans]
            result["ns"] = ns_hosts
            result["classification"] = classify(Risk.OK, "NS present", {"domain": base, "ns": ns_hosts}, confidence="MEDIUM")
            return result

        except dns.exception.Timeout as e:
            result["dns_error"] = f"DNS provider lookup failed: Timeout {e}"
            if self.mode == "loose":
                result["classification"] = classify(Risk.VULNERABLE, "Timeout (loose mode)", {"domain": base, "error": str(e)}, confidence="LOW")
            else:
                result["classification"] = classify(Risk.RETRY, "Timeout", {"domain": base, "error": str(e)})
            return result
        except Exception as e:
            result["dns_error"] = f"DNS provider lookup failed: {e}"
            result["classification"] = classify(Risk.ENV_ERROR, "Resolver failure", {"domain": base, "error": str(e)})
            return result

    def get_domain_owner(self, base_domain: str) -> Dict:
        out = {"whois_owner": None, "whois_registrar": None, "whois_error": None, "tls_cert": None}
        if whois is not None:
            try:
                with self._whois_lock:
                    since = time.time() - self._whois_last
                    if since < self.whois_delay:
                        time.sleep(self.whois_delay - since)
                    self._whois_last = time.time()
                with _NET_SEM:
                    w = whois.whois(base_domain)
                owner = w.get("org") or w.get("registrant_org") or w.get("registrant_name") or w.get("name")
                registrar = w.get("registrar")
                if isinstance(owner, list):
                    owner = owner[0] if owner else None
                if isinstance(registrar, list):
                    registrar = registrar[0] if registrar else None
                out["whois_owner"] = owner
                out["whois_registrar"] = registrar
            except Exception as e:
                out["whois_error"] = str(e)
        else:
            out["whois_error"] = "python-whois not available"
        cert_info = _get_cert_org(base_domain)
        if cert_info:
            out["tls_cert"] = cert_info
        return out

    def get_service_provider(self, hostname: str) -> Dict:
        svc = {"cname_chain": [], "ips": [], "ip_whois": None}
        chain = _resolve_cname_chain(hostname)
        svc["cname_chain"] = chain
        terminal = chain[-1] if chain else hostname
        ips = _resolve_ips(terminal)
        svc["ips"] = ips
        svc["loose_match_provider"] = any(terminal.lower().endswith(suf) for suf in PROVIDER_SUFFIXES)

        # IPWhois sampling (first N IPs)
        if ips and IPWhois is not None:
            info_primary = None
            for ip in ips[: self._whois_max_ips]:
                info = _ipwhois_lookup(ip)
                if info and not info_primary:
                    info_primary = info
            if info_primary:
                svc["ip_whois"] = {
                    "asn": info_primary.get("asn"),
                    "asn_description": info_primary.get("asn_description"),
                    "asn_country_code": info_primary.get("asn_country_code"),
                    "network_name": (info_primary.get("network") or {}).get("name"),
                    "raw": info_primary,  # keep raw for deeper analysis if needed
                }

        term_reg = _registrable_domain(terminal)
        base_reg = _registrable_domain(hostname)
        if term_reg and term_reg != base_reg:
            svc.setdefault("rdap", {})
            svc["rdap"][term_reg] = _rdap_query_domain(term_reg, mode=getattr(self, "rdap_mode", "fast"))
        return svc

    def _log_unknown_cloud(self, hostname: str, ips: List[str], ipw: dict):
        if not self._unknown_log_path:
            return
        try:
            asn = ipw.get("asn") or ""
            asn_desc = (ipw.get("asn_description") or "").replace(",", " ")
            net_name = ((ipw.get("network") or {}).get("name") or ipw.get("network_name") or "").replace(",", " ")
            for ip in (ips or []):
                key = (hostname, str(asn), ip)
                if key in self._unknown_seen:
                    continue
                line = f"{hostname},{ip},AS{asn},{asn_desc},{net_name}\n"
                with self._unknown_log_lock:
                    with open(self._unknown_log_path, "a", encoding="utf-8") as fh:
                        fh.write(line)
                self._unknown_seen.add(key)
        except Exception:
            pass  # logging is best-effort only

    def analyze(self, hostname: str) -> dict:
        ext = tldextract.extract(hostname)
        base_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname
        dns_provider = self.get_dns_provider(base_domain)
        domain_owner = self.get_domain_owner(base_domain)
        service_provider = self.get_service_provider(hostname)

        # Provider/cloud classification
        ipw_raw = (service_provider.get("ip_whois") or {}).get("raw") or (service_provider.get("ip_whois") or {})
        is_cloud = _is_cloud_provider(ipw_raw, self._providers_cfg) if ipw_raw else False
        takeover_type = "UNKNOWN"

        # Optional HTTP/TLS probe (enabled via CLI)
        http_probe = None
        fp_conf = "none"
        fp_names: List[str] = []
        if self.http_probe_enabled and service_provider.get("ips"):
            target_ips = (service_provider.get("ips") or [])[: self.http_max_ips]
            http_probe = _probe_http_suite(
                hostname=hostname,
                ips=target_ips,
                timeout=self.http_timeout,
                no_sni=self.no_sni,
                fps=self._fps
            )
            fp_names = http_probe.get("fingerprints") or []
            fp_conf = http_probe.get("confidence") or "none"

        # TCP states for first N IPs (always collected silently for CSV/JSON)
        tcp_states = _tcp_states_for_ips(service_provider.get("ips") or [], self.http_max_ips, self.http_timeout)

        # Base risk from DNS phase
        risk = dns_provider.get("classification", {}).get("risk", "OK")
        reason = dns_provider.get("classification", {}).get("reason", "NS present")

        # Loose-mode heuristic (existing)
        loose_vuln = False
        if self.mode == "loose" and service_provider.get("loose_match_provider"):
            loose_vuln = True

        # Candidate / Confirmed classification
        if is_cloud and (service_provider.get("cname_chain") == []):
            takeover_type = "A_CLOUD_REUSE_CANDIDATE"
            if fp_conf == "strong":
                takeover_type = "A_CLOUD_REUSE_CONFIRMED"
                risk = Risk.VULNERABLE.value
                reason = "A-record to cloud IP with default/unbound backend (confirmed by fingerprints)"
            elif self.mode == "loose" and fp_conf in ("weak", "medium"):
                loose_vuln = True
        else:
            if (service_provider.get("cname_chain") == []) and _looks_cloudy_but_unknown(ipw_raw, http_probe):
                self._log_unknown_cloud(hostname, service_provider.get("ips") or [], ipw_raw)

        hostname_ips = _resolve_ips(hostname)

        # Takeover confidence (new)
        takeover_confidence = _grade_takeover_confidence(
            takeover_type=takeover_type,
            http_probe=http_probe,
            tcp_states=tcp_states,
            mode=self.mode
        )

        return {
            "hostname": hostname,
            "base_domain": base_domain,
            "hostname_ips": hostname_ips,
            "dns_provider": dns_provider,
            "domain_owner": domain_owner,
            "service_provider": service_provider,
            "http_probe": http_probe,
            "tcp_states": tcp_states,                # kept out of console; used in CSV/JSON
            "takeover_type": takeover_type,
            "takeover_confidence": takeover_confidence,
            "http_fingerprints": fp_names,
            "loose_vulnerable": loose_vuln,
            "mode": self.mode,
            "rdap_mode": self.rdap_mode,
        }
