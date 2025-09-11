import os
import socket
import ssl
import time
import threading
from enum import Enum
from typing import Dict, List, Optional

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
# DNS resolver helpers
# =============================
_PUBLIC_RESOLVER_POOLS: List[List[str]] = [
    ["8.8.8.8", "8.8.4.4"],
    ["1.1.1.1", "1.0.0.1"],
    ["9.9.9.9", "149.112.112.112"],
]

def _make_resolver(timeout: float = 3.0, lifetime: float = 5.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)  # bypass /etc/resolv.conf
    pool = _PUBLIC_RESOLVER_POOLS[os.getpid() % len(_PUBLIC_RESOLVER_POOLS)]
    r.nameservers = pool
    r.timeout = float(os.environ.get("DNS_TIMEOUT", timeout))
    r.lifetime = float(os.environ.get("DNS_LIFETIME", lifetime))
    return r

def _resolve_with_retries(name: str, rtype: str, attempts: int = 3, raise_on_no_answer: bool = False):
    last_exc = None
    for i in range(attempts):
        try:
            with _NET_SEM:
                res = _make_resolver().resolve(name, rtype, raise_on_no_answer=raise_on_no_answer)
            return res
        except dns.exception.Timeout as e:
            last_exc = e
            if i == attempts - 1:
                raise
            continue
        except dns.resolver.NoNameservers as e:
            last_exc = e
            if i == attempts - 1:
                raise
        except Exception as e:
            last_exc = e
            if i == attempts - 1:
                raise
    if last_exc:
        raise last_exc

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
# CNAME chain resolver
# =============================
def _resolve_cname_chain(hostname: str, max_hops: int = 10) -> List[str]:
    chain: List[str] = []
    current = hostname.rstrip(".")
    for _ in range(max_hops):
        try:
            ans = _resolve_with_retries(current, "CNAME", attempts=2, raise_on_no_answer=False)
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
        ans = _resolve_with_retries(name, "A", attempts=2, raise_on_no_answer=False)
        if ans and getattr(ans, "rrset", None):
            ips.extend([r.address for r in ans])
    except Exception:
        pass
    try:
        ans6 = _resolve_with_retries(name, "AAAA", attempts=2, raise_on_no_answer=False)
        if ans6 and getattr(ans6, "rrset", None):
            ips.extend([r.address for r in ans6])
    except Exception:
        pass
    return ips

# =============================
# RDAP helpers
# =============================
_RDAP_BOOTSTRAP_URL = os.environ.get("RDAP_BOOTSTRAP_URL", "https://data.iana.org/rdap/dns.json")
_RDAP_HTTP_TIMEOUT = float(os.environ.get("RDAP_TIMEOUT", "5.0"))

import json
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

def _rdap_query_domain(domain: str, mode: str = "fast") -> dict:
    ext = tldextract.extract(domain)
    suffix = ext.suffix
    if not suffix:
        return {"error": "no suffix"}
    urls = _rdap_base_urls_for_suffix(suffix)
    if not urls:
        return {"error": f"no rdap urls for suffix {suffix}"}

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
                    return {"found": False, "status_code": 404, "server": base}
                if resp.ok:
                    data = resp.json()
                    statuses = data.get("status") or []
                    return {"found": True, "ldhName": data.get("ldhName"), "handle": data.get("handle"), "status": statuses, "server": base}
                if resp.status_code in (429, 502, 503, 504) and mode == "polite":
                    ra = resp.headers.get("Retry-After")
                    delay = float(ra) if (ra and ra.isdigit()) else backoff
                    time.sleep(delay)
                    backoff = min(backoff * 2.0, 8.0)
                    continue
                return {"found": None, "status_code": resp.status_code, "server": base}
            except requests.RequestException as e:
                if mode == "polite":
                    time.sleep(backoff)
                    backoff = min(backoff * 2.0, 8.0)
                    continue
                return {"error": str(e)}
    return {"error": "rdap query failed"}

# =============================
# Ownership Middleware
# =============================
PROVIDER_SUFFIXES = [
    ".github.io", ".githubusercontent.com", ".herokuapp.com", ".netlify.app",
    ".vercel.app", ".cloudfront.net", ".s3.amazonaws.com", ".s3-website", ".azurewebsites.net",
    ".trafficmanager.net", ".blob.core.windows.net", ".storage.googleapis.com"
]

class OwnershipMiddleware:
    def __init__(self, whois_delay: float = 1.0, mode: str = "strict", rdap_mode: str = "fast"):
        self.whois_delay = whois_delay
        self.mode = mode
        self.rdap_mode = rdap_mode
        self._whois_lock = threading.Lock()
        self._whois_last = 0.0

    # DNS provider
    def get_dns_provider(self, domain: str) -> Dict:
        base = _registrable_domain(domain)
        result = {"ns": [], "dns_error": None, "classification": classify(Risk.OK, "NS present", {})}
        try:
            try:
                ans = _resolve_with_retries(base, "NS", attempts=3, raise_on_no_answer=False)
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
        out = {"whois_owner": None, "whois_error": None, "tls_cert": None}
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
                if isinstance(owner, list):
                    owner = owner[0] if owner else None
                out["whois_owner"] = owner
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
        if ips and IPWhois is not None:
            info = _ipwhois_lookup(ips[0])
            if info:
                svc["ip_whois"] = {
                    "asn": info.get("asn"),
                    "asn_description": info.get("asn_description"),
                    "network_name": (info.get("network") or {}).get("name"),
                }
        # RDAP check for terminal registrable domain
        term_reg = _registrable_domain(terminal)
        base_reg = _registrable_domain(hostname)
        if term_reg and term_reg != base_reg:
            svc.setdefault("rdap", {})
            svc["rdap"][term_reg] = _rdap_query_domain(term_reg, mode=getattr(self, "rdap_mode", "fast"))
        return svc

    def analyze(self, hostname: str) -> dict:
        ext = tldextract.extract(hostname)
        base_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname
        dns_provider = self.get_dns_provider(base_domain)
        domain_owner = self.get_domain_owner(base_domain)
        service_provider = self.get_service_provider(hostname)
        loose_vuln = False
        if self.mode == "loose" and service_provider.get("loose_match_provider"):
            loose_vuln = True
        return {
            "hostname": hostname,
            "base_domain": base_domain,
            "dns_provider": dns_provider,
            "domain_owner": domain_owner,
            "service_provider": service_provider,
            "loose_vulnerable": loose_vuln,
            "mode": self.mode,
            "rdap_mode": self.rdap_mode,
        }
