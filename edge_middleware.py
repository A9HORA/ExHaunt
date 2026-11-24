"""edge_middleware.py — dangling-edge detection and claimability context (ExHaunt v1.1.0).

Why this exists: a CNAME chain that ends on a CDN/SaaS edge name which resolves to NO address never produces an
HTTP response, so none of the HTTP fingerprints can fire and the host used to be printed `OK`. Observed 2026-11-24 on
ten `*.qad.priceline.com` names → `qad.priceline.com.cdn.cloudflare.net` (removed Cloudflare partial zone): every row
came back `OK / UNKNOWN / none`. `OK` there meant "no rule", not "safe".

What it adds (all read-only, DNS + public endpoints; nothing is created anywhere):
  * final-target rcode (NXDOMAIN vs NOANSWER vs SERVFAIL …) — different claimability cases
  * edge-provider match from edges.yaml → BROKEN "dangling edge" + per-provider claim requirements
  * wildcard detection (does a random sibling label resolve to the same target?)
  * stale verification TXT lookups (cloudflare-verify.<host>, asuid.<host>, _dnsauth.<host>, …)
  * SNI/Host probe against the provider's anycast edge when the target has no address, so the existing
    provider fingerprints (e.g. Cloudflare "Error 1001") can still identify the provider
  * optional certificate-transparency check (--ct): last certificate issued for the host (crt.sh)
  * optional Cloudflare owner-side checks (--cf-token / CLOUDFLARE_API_TOKEN): is the zone present in our
    account(s), does the apex zone hold cover subdomains
"""
import os
import random
import re
import string
import time
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver
import requests

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

from ownership_middleware import (
    _resolve_with_multi_fallback, _http_request_raw, _match_fingerprints, _registrable_domain, _NET_SEM, _warn,
)


# ---------------------------------------------------------------- edges table
def load_edges(path: Optional[str]) -> List[dict]:
    # precedence: explicit --edges-file › $EXHAUNT_EDGES_FILE (Docker ships /edges.yaml) › bundled file beside this module
    p = path if (path and os.path.isfile(path)) else (os.environ.get("EXHAUNT_EDGES_FILE") or path or os.path.join(os.path.dirname(__file__), "edges.yaml"))
    if yaml is None or not os.path.isfile(p):
        if yaml is None:
            _warn("PyYAML not installed; edge-provider table disabled (dangling-edge detection off).")
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        out = []
        for e in data if isinstance(data, list) else []:
            if not isinstance(e, dict) or not e.get("suffixes"):
                continue
            e = dict(e)
            e["suffixes"] = [str(s).lower() for s in e.get("suffixes") or []]
            e["dangling_rcode"] = [str(s).upper() for s in e.get("dangling_rcode") or ["NXDOMAIN"]]
            out.append(e)
        return out
    except Exception as ex:
        _warn(f"Failed to read edges file {p}: {ex}; dangling-edge detection off.")
        return []


def match_edge(terminal: str, edges: List[dict]) -> Optional[dict]:
    t = (terminal or "").lower().rstrip(".")
    for e in edges:
        for suf in e["suffixes"]:
            if t.endswith(suf):
                return e
    return None


# ---------------------------------------------------------------- DNS detail
def resolve_ips_detail(name: str) -> Tuple[List[str], str]:
    """Return (ips, rcode) where rcode ∈ NOERROR | NOANSWER | NXDOMAIN | SERVFAIL | TIMEOUT | ERROR."""
    ips: List[str] = []
    rcode = "NOANSWER"
    for rtype in ("A", "AAAA"):
        try:
            ans = _resolve_with_multi_fallback(name, rtype, attempts=2, raise_on_no_answer=False)
            if ans and getattr(ans, "rrset", None):
                ips.extend([r.address for r in ans]); rcode = "NOERROR"
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN"
        except dns.resolver.NoNameservers:
            rcode = "SERVFAIL"
        except dns.exception.Timeout:
            rcode = "TIMEOUT" if rcode == "NOANSWER" else rcode
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            rcode = "ERROR" if rcode == "NOANSWER" else rcode
    return ips, rcode


def txt_values(name: str, limit: int = 3) -> List[str]:
    try:
        ans = _resolve_with_multi_fallback(name, "TXT", attempts=1, raise_on_no_answer=False)
        if not ans or not getattr(ans, "rrset", None):
            return []
        vals = []
        for r in ans:
            s = b"".join(getattr(r, "strings", []) or []).decode(errors="ignore")
            vals.append(s[:12] + "…" if len(s) > 12 else s)  # value prefix only — never print a full key
        return vals[:limit]
    except Exception:
        return []


def verification_records(hostname: str, edge: Optional[dict], terminal: str = "") -> Dict[str, List[str]]:
    """Look up the verification TXT names a legitimate owner would have published. A leftover record is evidence the
    service existed and was removed; it is also the record the fix must delete."""
    host = hostname.rstrip(".")
    apex = _registrable_domain(host)
    # {zone} = the provider-side zone name, derived from the terminal CNAME minus the edge suffix
    # (qad.priceline.com.cdn.cloudflare.net → qad.priceline.com); a Cloudflare verify TXT sits at the zone, not the host
    zone = ""
    term = (terminal or "").lower().rstrip(".")
    for suf in (edge or {}).get("suffixes") or []:
        if term.endswith(suf):
            zone = term[: -len(suf)]
            break
    names: List[str] = []
    for tmpl in (edge or {}).get("verification_txt") or []:
        t = str(tmpl)
        if "{zone}" in t and not zone:
            continue
        names.append(t.replace("{host}", host).replace("{apex}", apex).replace("{zone}", zone))
    names.append(f"_acme-challenge.{host}")
    out: Dict[str, List[str]] = {}
    for n in dict.fromkeys(names):
        v = txt_values(n)
        if v:
            out[n] = v
            continue
        # no TXT — is the name swallowed by a wildcard CNAME? (then no TXT can be published there without removing the wildcard)
        try:
            c = _resolve_with_multi_fallback(n, "CNAME", attempts=1, raise_on_no_answer=False)
            if c and getattr(c, "rrset", None):
                out[n] = [f"no TXT — answered by CNAME {str(c[0].target).rstrip('.')} (wildcard?)"]
        except Exception:
            pass
    return out


def wildcard_check(hostname: str, chain: List[str], ips: List[str]) -> dict:
    """Resolve a random sibling label under the parent; if it reaches the same CNAME terminal or the same IPs, the
    host is served by a wildcard record — scope is 'every name under the parent', not this one host."""
    host = hostname.rstrip(".")
    labels = host.split(".")
    if len(labels) < 3:
        return {"checked": False}
    parent = ".".join(labels[1:])
    probe = "exh-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "." + parent
    try:
        c = _resolve_with_multi_fallback(probe, "CNAME", attempts=1, raise_on_no_answer=False)
        target = str(c[0].target).rstrip(".") if (c and getattr(c, "rrset", None)) else None
    except dns.resolver.NXDOMAIN:
        return {"checked": True, "via_wildcard": False, "parent": parent}
    except Exception:
        target = None
    same_cname = bool(target and chain and target.lower() == chain[0].lower())
    same_ips = False
    if not same_cname and ips:
        pips, _ = resolve_ips_detail(probe)
        same_ips = bool(pips) and set(pips) == set(ips)
    return {"checked": True, "via_wildcard": bool(same_cname or same_ips), "parent": parent,
            "probe_target": target, "wildcard_scope": f"*.{parent}" if (same_cname or same_ips) else None}


# ---------------------------------------------------------------- SNI/Host probe against the provider edge
def edge_probe(hostname: str, edge: dict, fps: List[dict], timeout: float) -> dict:
    """When the CNAME target has no address, ask the provider's own anycast edge for the hostname (SNI + Host).
    The provider answers with its 'unknown hostname' page, which is what the HTTP fingerprints match."""
    out = {"per_ip": {}, "fingerprints": [], "confidence": "none", "any_vulnerable": False}
    rank = {"none": 0, "weak": 1, "medium": 2, "strong": 3}
    # probe targets: a live edge name under the same apex (e.g. www.<apex>.cdn.cloudflare.net) answers for the
    # provider's real CNAME-setup edge; static anycast IPs are the fallback
    targets: List[str] = []
    apex = _registrable_domain(hostname)
    for tmpl in edge.get("probe_edge_names") or []:
        name = str(tmpl).replace("{apex}", apex)
        ips, _ = resolve_ips_detail(name)
        for ip in ips[:1]:
            if ip not in targets:
                targets.append(ip)
    for ip in edge.get("probe_edges") or []:
        if ip not in targets:
            targets.append(ip)
    for ip in targets[:3]:
        st, hdrs, body, tls = _http_request_raw(ip, hostname, 443, use_tls=True, use_sni=True, timeout=timeout)
        if st is None and not hdrs and not body:
            st, hdrs, body, tls = _http_request_raw(ip, hostname, 80, use_tls=False, use_sni=False, timeout=timeout)
        if st is None and not hdrs and not body:
            out["per_ip"][ip] = {"status": None}
            continue
        names, conf, vuln = _match_fingerprints(st, hdrs, body, tls, fps)
        out["per_ip"][ip] = {"status": st, "server": hdrs.get("server"), "fingerprints": names}
        out["fingerprints"] = sorted(set(out["fingerprints"] + names))
        out["confidence"] = max(out["confidence"], conf, key=lambda c: rank[c])
        out["any_vulnerable"] = out["any_vulnerable"] or vuln
    return out


# ---------------------------------------------------------------- certificate transparency (optional)
_CT_CACHE: Dict[str, dict] = {}
_CT_LOCK_TS = [0.0]


def ct_last_certificate(hostname: str, timeout: float = 20.0) -> dict:
    """crt.sh lookup: number of entries and the newest not_before / not_after for the exact host. 'No certificate
    issued since <date>' is a cheap negative indicator that nobody has activated the name since it went dangling."""
    host = hostname.rstrip(".").lower()
    if host in _CT_CACHE:
        return _CT_CACHE[host]
    res: dict = {"checked": True}
    try:
        # be polite: crt.sh is a shared service
        gap = time.time() - _CT_LOCK_TS[0]
        if gap < 1.0:
            time.sleep(1.0 - gap)
        _CT_LOCK_TS[0] = time.time()
        r = None
        for attempt in range(2):  # crt.sh answers 502/503 under load — one polite retry
            with _NET_SEM:
                r = requests.get("https://crt.sh/", params={"q": host, "output": "json"}, timeout=timeout,
                                 headers={"User-Agent": "ExHaunt/1.1 (+https://github.com/A9HORA/ExHaunt)"})
            if r.status_code < 500:
                break
            time.sleep(2.0 + attempt * 2.0)
        if r.status_code != 200:
            res.update({"error": f"crt.sh HTTP {r.status_code}"})
        else:
            rows = r.json() if r.text.strip() else []
            exact = [x for x in rows if host in {n.strip().lower() for n in str(x.get("name_value", "")).split("\n")}]
            nb = sorted((x.get("not_before") or "")[:10] for x in exact if x.get("not_before"))
            na = sorted((x.get("not_after") or "")[:10] for x in exact if x.get("not_after"))
            res.update({"entries": len(exact), "last_not_before": nb[-1] if nb else None,
                        "last_not_after": na[-1] if na else None})
    except Exception as e:
        res.update({"error": str(e)[:120]})
    _CT_CACHE[host] = res
    return res


# ---------------------------------------------------------------- Cloudflare owner-side checks (optional)
def cloudflare_owner_checks(hostname: str, token: Optional[str], timeout: float = 15.0) -> dict:
    """With an API token for the *defender's* Cloudflare account(s): is any candidate zone for this host present,
    and does the apex zone hold cover subdomains. Read-only (GET /zones, GET /zones/{id}/hold)."""
    if not token:
        return {"checked": False, "note": "no Cloudflare token (--cf-token or CLOUDFLARE_API_TOKEN)"}
    host = hostname.rstrip(".").lower()
    apex = _registrable_domain(host)
    labels = host.split(".")
    candidates = []
    for i in range(len(labels)):
        c = ".".join(labels[i:])
        if c.endswith(apex):
            candidates.append(c)
        if c == apex:
            break
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    out: dict = {"checked": True, "zones_present": {}, "apex_hold": None}
    try:
        for name in candidates:
            with _NET_SEM:
                r = requests.get("https://api.cloudflare.com/client/v4/zones", params={"name": name}, headers=hdr, timeout=timeout)
            if r.status_code != 200:
                out["error"] = f"zones HTTP {r.status_code}"; break
            zones = (r.json() or {}).get("result") or []
            out["zones_present"][name] = [{"status": z.get("status"), "type": z.get("type"),
                                           "account": (z.get("account") or {}).get("name")} for z in zones]
            if name == apex and zones:
                zid = zones[0].get("id")
                with _NET_SEM:
                    h = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zid}/hold", headers=hdr, timeout=timeout)
                if h.status_code == 200:
                    res = (h.json() or {}).get("result") or {}
                    out["apex_hold"] = {"hold": res.get("hold"), "include_subdomains": res.get("include_subdomains"),
                                        "hold_after": res.get("hold_after")}
                else:
                    out["apex_hold"] = {"error": f"hold HTTP {h.status_code}"}
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


# ---------------------------------------------------------------- the rule
def dangling_edge_assessment(hostname: str, chain: List[str], ips: List[str], rcode: str, edges: List[dict],
                             fps: List[dict], mode: str, http_timeout: float, want_ct: bool, cf_token: Optional[str]) -> Optional[dict]:
    """Return an `edge` block when the terminal CNAME is a known edge with no address, else None."""
    if not chain or ips:
        return None
    terminal = chain[-1]
    edge = match_edge(terminal, edges)
    if not edge:
        return None
    rc = (rcode or "NOANSWER").upper()
    dangling = rc in edge.get("dangling_rcode", ["NXDOMAIN"]) or rc in ("NXDOMAIN", "NOANSWER")
    block = {
        "provider": edge.get("provider"), "slug": edge.get("slug"), "terminal": terminal, "target_rcode": rc,
        "dangling": dangling, "claimable_by_free_account": edge.get("claimable_by_free_account"),
        "claim_requirements": edge.get("claim_requirements") or [], "docs": edge.get("docs") or [],
    }
    block["verification_records"] = verification_records(hostname, edge, terminal)
    block["wildcard"] = wildcard_check(hostname, chain, ips)
    if edge.get("probe_edges"):
        block["edge_probe"] = edge_probe(hostname, edge, fps, http_timeout)
    if want_ct:
        block["ct"] = ct_last_certificate(hostname)
    if (edge.get("slug") or "").startswith("cloudflare"):
        block["cloudflare_owner_checks"] = cloudflare_owner_checks(hostname, cf_token)
    return block


def grade_edge_confidence(block: dict, mode: str) -> str:
    """low = dangling but claim needs a paid plan / owner-side verification; medium = provider identified by the edge
    probe or claimable by a free account; high is never given here — only a claim in an owned account proves it."""
    if not block or not block.get("dangling"):
        return "none"
    claim = str(block.get("claimable_by_free_account")).lower()
    probe_hit = bool((block.get("edge_probe") or {}).get("fingerprints"))
    if claim == "true":
        return "medium"
    if claim == "conditional":
        return "medium" if (probe_hit or mode == "loose") else "low"
    return "low"
