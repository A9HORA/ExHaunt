# ExHaunt 👻 by a9hora

*Find and classify dangling subdomains before they haunt you.*

ExHaunt an analyst's tool helps you discover **dangling subdomains** (CNAMEs pointing to unclaimed services or dead domains) and sorts them into clear buckets:
`OK`, `VULNERABLE`, `BROKEN`, `RETRY`, `ENV_ERROR`. Each result comes with evidence and confidence.

> Built & maintained by **[A9HORA](https://twitter.com/A9HORA)**

---

## ✨ Features & Roadmap

### ✅ Existing
- [x] **DNS resolution with retries & fallbacks** — ensures reliability across resolvers.  
- [x] **RDAP lookups (`fast` / `polite`)** — confirms domain availability with configurable accuracy vs. speed.  
- [x] **WHOIS ownership lookups with delay** — provides registrar/owner context without overwhelming servers.  
- [x] **CNAME chain detection** — surfaces the final service a subdomain resolves to.  
- [x] **IPWhois enrichment** — ASN and network data helps identify hosting providers.  
- [x] **TLS certificate fallback** — extracts cert subject/issuer when WHOIS is masked.  
- [x] **Strict vs Loose detection modes** — balances accuracy vs. exploratory hunting.  
- [x] **Classification matrix** (`OK`, `VULNERABLE`, `BROKEN`, `RETRY`, `ENV_ERROR`) — clear triage categories.  
- [x] **Color-coded live and summary output** — fast visual scanning of vulnerable subs.  
- [x] **CSV + JSON reports** — easy integration with spreadsheets and other tools.  
- [x] **Progress bar & logging** — user-friendly tracking for large lists.  

### 🔮 Upcoming
- [ ] **Provider HTTP fingerprinting** — detect “unclaimed” error pages (S3, GitHub Pages, Azure, etc.) for strict, high-confidence vuln confirmation.  
- [ ] **`--skip-whois` flag** — faster scans, cleaner logs when ownership info isn’t needed.  
- [ ] **`--only-vulnerable` flag** — print/export only vulnerable subs for CI/CD or bug bounty workflows.  
- [ ] **CSV flattening for nested fields** — dotted keys like `dns_provider.classification.risk` for easier spreadsheet use.  
- [ ] **Fingerprint library in YAML/JSON** — community-driven updates without touching Python code.  
- [ ] **Export to Markdown/HTML report** — human-readable bug bounty & audit reports.  
- [ ] **Configurable retry/backoff policies** — fine-tune RDAP/WHOIS behavior per environment.  
- [ ] **Docker image release** — one-liner deployment (`docker run a9hora/exhaunt`).  
- [ ] **CI/CD integration hooks (GitHub Actions template)** — continuous monitoring of your zones.  
- [ ] **Domain auto-expansion** (`*.domain.com` integration with Amass/Subfinder) — all-in-one discovery + takeover check.  
- [ ] **Severity scoring** — rank vulns by confidence/severity for easier triage.  

---

## 🧭 Quick Start Cheat Sheet

> **New to ExHaunt?**
>
> * `--mode strict` = fewer, high-confidence vulns.
> * `--mode loose` = more hits, includes weaker signals (exploratory).
> * `--rdap-mode fast` = quickest, single registry query.
> * `--rdap-mode polite` = retries with backoff for better availability accuracy.
> * WHOIS errors **do not** affect vulnerability classification (DNS + RDAP decide).

---

## ⚙️ Usage

```bash
python3 exhaunt.py [OPTIONS]
```

### Input (required)

* `--file FILE` — read subdomains from a file (one per line)
  → Outputs: `FILE.json`, `FILE.csv`
* `--subs SUB [SUB ...]` — pass subdomains directly
  → Outputs: `console_input.json`, `console_input.csv`

### Detection Modes

* `--mode strict` *(default)* — **hard evidence only** (NXDOMAIN + RDAP confirms unregistered)
* `--mode loose` — **also haunts suspicious but unproven cases** (timeouts, empty NS, provider suffix suspects)

### RDAP Modes

* `--rdap-mode fast` *(default)* — single RDAP try per registry (fastest)
* `--rdap-mode polite` — retries with exponential backoff, honors `Retry-After` (slower, more resilient)

### WHOIS

* `--whois-delay SECONDS` *(default: 1.0)* — minimum spacing between WHOIS queries across threads
  Raise to 2.0–3.0s if you see rate-limit errors in logs.

### Performance

* `--threads N` — number of worker threads (default: 10)
* `--threads auto` — up to min(64, 2 × CPU); recommended for large lists

### Output & Display

* `--color` — live red alerts while scanning

  * Strict: only strong evidence
  * Loose: also suspicious provider suffixes
* `--quiet` — hides progress bar (CI-friendly)
* `--logfile FILE` — write progress messages to a file

---

## 📊 Classification

* **OK** — DNS healthy
* **VULNERABLE** —

  * Strict: NXDOMAIN + RDAP says not found (high confidence)
  * Loose: also weaker signals (timeouts, empty NS, provider suffix suspects)
* **BROKEN** — Delegation/config errors (SERVFAIL, empty NS with SOA)
* **RETRY** — Resolver timeout
* **ENV\_ERROR** — Local/system resolver issue

---

## 🚀 Examples

### Baseline (fast, balanced)

```bash
python3 exhaunt.py \
  --file subs.txt \
  --threads auto \
  --mode strict \
  --rdap-mode fast \
  --whois-delay 1.5 \
  --quiet
```

### Thorough audit (best accuracy)

```bash
python3 exhaunt.py \
  --file subs.txt \
  --threads auto \
  --mode strict \
  --rdap-mode polite \
  --whois-delay 1.5 \
  --quiet
```

### Exploratory hunting (more suspects)

```bash
python3 exhaunt.py \
  --file subs.txt \
  --threads auto \
  --mode loose \
  --rdap-mode fast \
  --whois-delay 1.0 \
  --color
```

### Direct subdomains

```bash
python3 exhaunt.py \
  --subs www.example.com api.example.com \
  --mode strict \
  --rdap-mode fast
```

### CI-friendly

```bash
python3 exhaunt.py \
  --file subs.txt \
  --mode strict \
  --rdap-mode fast \
  --quiet \
  --logfile run.log
```

---

## 🧠 Best Practices

* For **10k+ subdomains**:

  1. First pass: `--mode strict --rdap-mode fast --threads auto --quiet`
  2. Re-run only `RETRY`/targeted TLDs with `--rdap-mode polite`

* Increase `--whois-delay` to 2–3s if you see many WHOIS errors.

* Use `--mode loose` to surface suspects; stick to `strict` for evidence-based tickets.

---

## ❓ Troubleshooting

**Lots of WHOIS errors**
That’s normal under load (registries rate-limit). ExHaunt bases risk on DNS + RDAP; WHOIS is just ownership context.

**Slow on huge lists**
Use `--threads auto` and `--rdap-mode fast`, then re-run inconclusives with `--rdap-mode polite`.

**“Suspicious provider suffix (haunted)”**
Loose mode hint: terminal CNAME points at known providers. Treat as a lead, not proof.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Attribution

ExHaunt 👻 is developed and maintained by **[a9hora](https://github.com/a9hora)**.  

If you use ExHaunt in research, products, company workflows, or publications, please provide clear attribution to the project and its author.
