# ExHaunt 👻 by a9hora

*Find and classify dangling subdomains before they haunt you.*

ExHaunt helps you identify **risky, abandoned, or misconfigured subdomains** before attackers take advantage of them.
It sorts each subdomain into clear categories — `OK`, `VULNERABLE`, `BROKEN`, `RETRY`, `ENV_ERROR` — and assigns a **confidence level** so you understand which findings truly matter.

> Built & maintained by **A9HORA**

---

## ✨ Features & Roadmap

### ✅ Existing

* [x] **DNS resolution with retries & fallbacks** — ensures reliability across resolvers.
* [x] **RDAP lookups (`fast` / `polite`)** — confirms domain availability with configurable accuracy vs. speed.
* [x] **WHOIS ownership lookups with delay** — provides registrar/owner context without overwhelming servers.
* [x] **CNAME chain detection** — surfaces the final service a subdomain resolves to.
* [x] **IPWhois enrichment** — ASN and network data helps identify hosting providers.
* [x] **TLS certificate fallback** — extracts cert subject/issuer when WHOIS is masked.
* [x] **Strict vs Loose detection modes** — balances accuracy vs. exploratory hunting.
* [x] **Classification matrix** (`OK`, `VULNERABLE`, `BROKEN`, `RETRY`, `ENV_ERROR`) — clear triage categories.
* [x] **Color-coded live and summary output** — fast visual scanning of interesting subdomains.
* [x] **CSV + JSON reports** — easy integration with spreadsheets and other tools.
* [x] **Progress bar & logging** — user-friendly tracking for large lists.
* [x] **Takeover confidence grading** — low/medium/high hints for cloud IP reuse candidates.
* [x] **Compact JSON mode** — optional trimmed JSON output that keeps decision-critical fields but drops heavy debug blobs.
* [x] **TCP reachability probing (80/443)** — silent port checks surfaced in JSON/CSV for extra context.
* [x] **Container-ready single binary** — optional Docker image that packages ExHaunt as a self-contained CLI (no Python/runtime needed in the container).
* [x] **Provider HTTP fingerprinting** — identifies characteristic default responses from cloud services to strengthen takeover confirmation.
* [x] **External fingerprint library (YAML-based)** — supports customizable fingerprint rules without changing code `(extendable via fingerprints.yaml)`.

### 🔮 Upcoming

* **Expanded HTTP fingerprint coverage** — broader recognition of provider-specific default responses.
* **`--skip-whois` mode** — faster scans by disabling WHOIS ownership lookups when not needed.
* **`--only-vulnerable` output mode** — print or export only high-risk findings (ideal for CI/CD and bug bounty workflows).
* **Dot-notation CSV flattening** — advanced spreadsheet-friendly field mappings like dns_provider.ns[0].
* **Markdown/HTML reporting** — clean human-readable reports for auditors and leadership.
* **Enhanced retry/backoff tuning** — user-configurable DNS/RDAP/HTTP retry strategies.
* **CI/CD templates (GitHub Actions, GitLab, etc.)** — automated periodic scanning pipelines.
* **Domain expansion integrations** — optional pairing with external discovery tools (Amass, Subfinder).
* **Numerical severity scoring** — risk scoring system for automated prioritization.

---

## 🧭 Quick Start Cheat Sheet

* `--mode strict` = high-confidence findings only.
* `--mode loose` = exploratory, more suspicious leads.
* `--rdap-mode fast` = fastest.
* `--rdap-mode polite` = most reliable.
* WHOIS errors do **not** decide risk (DNS + registry do).

---

## ⚙️ Usage

```bash
python3 exhaunt.py [OPTIONS]
```

---

#### 🧭 Building Your Own Docker Image

ExHaunt has a Dockerfile that let's **you build your own docker image locally that requires no Python, no dependencies**.

Build the image:

```bash
docker build -t exhaunt .
```

Verify:

```bash
docker images | grep exhaunt
```
---

#### ⚙️ Run ExHaunt (Docker)

From your working directory:

```bash
docker run --rm -it \
  -v "$PWD":/workspace \
  exhaunt:latest \
  --file YourSubDomains.txt \
  --threads auto --whois-delay 2 --color \
  --mode strict --rdap-mode polite --print short \
  --http-probe --http-timeout 8 --http-retries 2 \
  --http-max-ips 3 --no-sni --whois-max-ips 5
```

Outputs (JSON + CSV) are written back to the **same directory** you mounted.

---

#### 🧩 Using Custom Providers / Fingerprints

Override built-in YAML files by mounting your own:

```bash
docker run --rm -it \
  -v "$PWD":/workspace \
  -v "$PWD/my-fingerprints.yaml":/fingerprints.yaml:ro \
  -v "$PWD/my-providers.yaml":/providers.yaml:ro \
  exhaunt:latest --file YourSubDomains.txt
```

Or mount a folder and point explicitly:

```bash
docker run --rm -it \
  -v "$PWD":/workspace \
  -v "$PWD/configs":/configs:ro \
  exhaunt:latest \
  --file YourSubDomains.txt \
  --fp-file /configs/fingerprints.yaml \
  --providers-file /configs/providers.yaml
```

---

#### 🐛 Troubleshooting

* **exec format error** → loaded wrong architecture (arm64 vs amd64)
* **file not found** → ensure the file exists in the mounted folder
* **permission denied (Linux)** → use: `-u $(id -u):$(id -g)`
* **docker: command not found** → install Docker Desktop/Engine

---

### Detection Modes

* `--mode strict` (default)
* `--mode loose`

### RDAP Modes

* `--rdap-mode fast` (default)
* `--rdap-mode polite`

### WHOIS

* `--whois-delay N` — prevent rate-limiting
* `--whois-max-ips N` — multi-IP ASN sampling

### HTTP/TLS Probing

* `--http-probe`
* `--no-sni`
* `--http-timeout N`
* `--http-retries N`
* `--http-max-ips N`
* `--fp-file FILE`

### Cloud Provider Matching

* `--providers-file FILE`
* `--add-cloud-marker REGEX`
* `--cloud-asn N`
* `--unknown-cloud-log FILE`

### Output & Display

* `--print {short, summary, both}`
* `--quiet`
* `--color`
* `--logfile FILE`
* `--json-compact`

### Performance

* `--threads N` or `auto`

---

## 📊 Classification

### Risk Levels

* **OK** — healthy
* **VULNERABLE** — confirmed risk
* **BROKEN** — DNS misconfiguration
* **RETRY** — temporary timeout
* **ENV_ERROR** — local/system issue

### Confidence Levels

* **none** — no evidence
* **low** — weak signals
* **medium** — moderate signals
* **high** — strong indicators

---

## 🚀 Examples

### Fast baseline

```bash
python3 exhaunt.py --file subs.txt --threads auto --mode strict --rdap-mode fast --quiet
```

### Full audit

```bash
python3 exhaunt.py --file subs.txt --threads auto --mode strict --rdap-mode polite \
--http-probe --http-timeout 6 --http-max-ips 3 --whois-max-ips 5 --color
```

### Exploration

```bash
python3 exhaunt.py --file subs.txt --mode loose --rdap-mode fast --http-probe --color
```

### Single host

```bash
python3 exhaunt.py --subs target.example.com --mode strict --http-probe --no-sni --rdap-mode polite
```

### CI mode

```bash
python3 exhaunt.py --file subs.txt --mode strict --json-compact --quiet --threads auto
```

---

## 🧠 Best Practices

* Use strict/fast for first passes on large inventories.
* Re-run RETRY cases with polite mode.
* Increase WHOIS delay if rate-limited.
* Use http-probe for confirmation scans.
* Loose mode for discovery; strict for reporting.
* json-compact for pipelines.

---

## ❓ Troubleshooting

* WHOIS errors are common and do not impact risk classification.
* DNS timeouts may require network tuning or fallback resolvers.
* Progress bar stays pinned; use --quiet for CI.
* Provider suffix hints are indicators, not confirmations.

---

## 📜 License

Licensed under the **ExHaunt Proprietary License** — no redistribution, no derivatives, contribution only with explicit permission.  
See [LICENSE](LICENSE) for full terms.

---

## 🙏 Attribution

ExHaunt 👻 maintained by **a9hora**.
Please attribute appropriately in reports or publications.
