# Changelog — ExHaunt

## 1.1.0 — 2026-11-24 — dangling edges are never `OK` again

Trigger: a HackerOne report on ten `*.qad.priceline.com` names whose CNAME chain ends at `qad.priceline.com.cdn.cloudflare.net`,
a removed Cloudflare partial zone. The target resolves to no address and answers no HTTP, so none of the fingerprints could
fire and every row came back `status=NS present | risk=OK | type=UNKNOWN | conf=none`. `OK` meant "no rule", not "safe".

### Added
- **Edge-provider table `edges.yaml`** (Cloudflare CNAME setup, CloudFront, Azure Front Door / Traffic Manager / App Service,
  Akamai, Fastly, GitHub Pages, Heroku, Netlify, Vercel): terminal suffixes, which rcode means "gone", whether a free account
  can claim it (`true` / `false` / `conditional`), the claim requirements in words, the verification TXT names a legitimate owner
  publishes, anycast edge IPs to probe, and the docs the requirements come from.
- **Dangling-edge rule.** CNAME chain ends on a known edge suffix + no A/AAAA ⇒ `BROKEN` with
  `takeover_type: <provider>-dangling-edge`, confidence `low` (paid plan / owner-side verification needed) or `medium`
  (free-account claim, or provider identified by the edge probe). `loose` mode promotes free-account cases to `VULNERABLE`.
  `high` is never given by this rule — only a claim in an account you own proves a takeover.
- **`UNKNOWN` bucket.** A CNAME that resolves to nothing and matches no edge rule is `UNKNOWN` ("no rule for this target"),
  never `OK`.
- **`target_rcode`** recorded for the final CNAME target: `NOERROR | NOANSWER | NXDOMAIN | SERVFAIL | TIMEOUT | ERROR`.
  NXDOMAIN on `cloudfront.net` and NOANSWER on `cdn.cloudflare.net` are different claimability cases.
- **Stale verification records.** `cloudflare-verify.<host>`, `asuid.<host>`, `_dnsauth.<host>`, `_vercel.<apex>`,
  `_acme-challenge.<host>` are looked up; a leftover record is evidence the service existed and is the record the fix must delete.
  Only a 12-character prefix of any value is kept.
- **Wildcard detection.** A random sibling label is resolved; if it reaches the same target the row says `via_wildcard=true`
  and `wildcard_scope=*.<parent>` — the exposure is every name under the parent, not the listed host.
- **Provider edge probe (SNI/Host).** When the target has no address, the provider's anycast edge is asked for the hostname so
  the existing provider fingerprints (e.g. Cloudflare `Error 1001`) can still identify the provider.
- **`--ct`**: crt.sh lookup per dangling host — entry count and the newest certificate dates. "No certificate since <date>" is a
  cheap negative indicator that nobody has activated the name since it went dangling. Polite: ~1 request/second, cached.
- **`--cf-token` / `CLOUDFLARE_API_TOKEN`**: read-only checks against *your* Cloudflare account(s) for `cdn.cloudflare.net`
  targets — is any candidate zone present, does the apex zone hold cover subdomains (`include_subdomains`).
- **Fingerprints:** `cloudflare-1016-plain`, `cloudflare-1001-plain`, `cloudflare-1003-direct-ip` — the plain-text bodies
  (`error code: 1016`) the edge returns to non-browser clients; identification only (`vulnerable: false`). A control probe showed
  1016 is returned for any unconfigured name under an apex that has a Cloudflare partial zone.
- **`probe_edge_names`** in `edges.yaml`: edge names resolved at run time (e.g. `www.{apex}.cdn.cloudflare.net`) are probed before
  the static anycast IPs, so the probe hits the provider's real CNAME-setup edge for that apex.
- Verification lookups report `cname-masked` when the verification name is swallowed by a wildcard CNAME — no TXT can be
  published there until the wildcard goes.
- **`--version`**, and the run header prints version, fingerprint count, edge-provider count, CT and Cloudflare-check state.
- CSV columns: `target_rcode, edge_provider, claimable_by_free_account, via_wildcard, verification_txt, ct_last_cert,
  cf_zone_present, cf_apex_hold_subdomains`. JSON: an `edge` block per dangling host.
- Live and summary lines print `[BROKEN]` (yellow) and `[UNKNOWN]` (blue) rows with the edge context.

### Changed
- `OwnershipMiddleware` takes `edges_file`, `want_ct`, `cf_token`.
- `README.md`: classification table gains `UNKNOWN` and the dangling-edge meaning of `BROKEN`; new flags documented.

### Unchanged
- Every existing rule, flag and output column. Hosts that resolve to an address are classified exactly as before.
- Nothing is written to any provider: all new checks are DNS, HTTPS GETs to public endpoints, and read-only API GETs.
