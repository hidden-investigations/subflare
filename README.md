# Subflare – Modern Subdomain Recon Tool

> **Fast passive recon + reliable DNS validation + automation-friendly output**  
> Built for practical offensive security and defensive asset discovery workflows.

```bash

███████╗██╗   ██╗██████╗ ███████╗██╗      █████╗ ██████╗ ███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝
███████╗██║   ██║██████╔╝█████╗  ██║     ███████║██████╔╝█████╗
╚════██║██║   ██║██╔══██╗██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
███████║╚██████╔╝██████╔╝██║     ███████╗██║  ██║██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

        @sakibulalikhan
    Hiddeninvestigations.Net
```

![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-Apache%202.0-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blueviolet)
![Passive Sources](https://img.shields.io/badge/Passive%20Sources-25-success)

---

## ⚠️ Legal & Ethical Disclaimer

Subflare is provided for **authorized security testing and asset discovery only**.

- Use this tool only on:
  - infrastructure you own, or
  - targets where you have explicit written permission.
- Do **not** run unauthorized scans against third-party systems.
- The authors and Hidden Investigations are not responsible for misuse.

By using this project, you agree to follow all applicable laws and regulations.

---

## Features

- ⚡ **High-speed passive recon** across 25 integrated sources
- 🧠 **Source runtime controls**: retries, backoff, rate limits, per-source timeout
- 🗂️ **Passive cache layer + persistent cache index** for faster reruns on large scopes
- 🔁 **Recursive bruteforce + smart permutations** for deeper host expansion
- 🌐 **DNS validation pipeline** with resolver health scoring
- 🚀 **Pluggable DNS backend** (`standard` or `massdns`)
- 🔎 **Reverse DNS expansion** to discover additional in-scope hosts
- 🧹 **Wildcard filtering** + trusted-resolver revalidation
- 🛰️ **Infrastructure enrichment** with ASN/CDN hints (`--enrich-infra`)
- 🌍 **HTTP probe handoff** (status, title, basic technology hints)
- 🛡️ **Takeover signal checks** with confidence scoring (`low`/`medium`/`high`)
- 🔄 **Fingerprint update mode** (`--update-fingerprints`) for takeover rules
- 🎯 **Takeover-only mode** for checking existing subdomain lists (`--takeover`)
- ⚙️ **Adaptive concurrency** (`--auto-tune`) based on observed failure rate
- 🧾 **Production-friendly CLI UX** with structured summary, result, and takeover sections
- 📊 **Readable scan summary** for operator workflow
- 🤖 **Automation mode** with strict stdout-only output
- 🧪 Workflow commands:
  - `bench` for throughput benchmarking
  - `diff` for old/new result comparison
  - `monitor` for scheduled recon and webhook alerts

---

## Requirements

- Go `1.23+`
- Network connectivity for passive source APIs and DNS
- Optional API keys for premium providers (recommended)

---

## Installation

### Option 1: Install with Go (recommended)

```bash
go install -v github.com/hidden-investigations/subflare/cmd/subflare@latest
```

Then run:

```bash
subflare --help
```

### Option 2: Build from source

1. Clone repository:

```bash
git clone https://github.com/hidden-investigations/subflare.git
cd subflare
```

2. Build binary:

```bash
go mod tidy
go build -o subflare ./cmd/subflare
```

3. Verify:

```bash
subflare --help
```

---

## Usage

Basic run:

```bash
subflare -d example.com
```

With selected sources:

```bash
subflare -d example.com --sources crtsh,anubis,securitytrails
```

Automation-safe output:

```bash
cat domains.txt | subflare --stdin --strict-io --no-banner
```

---

## Commands

| Command | Description |
|--------|-------------|
| `subflare` | Run scan pipeline |
| `subflare bench` | Benchmark passive + resolver throughput |
| `subflare diff` | Compare old/new output files |
| `subflare monitor` | Scheduled scans + delta alerting |

---

## Command Line Options

### Core target & mode options

| Option | Description | Default |
|-------|-------------|---------|
| `-d`, `--domain` | Target root domain | required unless `--stdin`, `-l`, `--takeover`, or `--update-fingerprints` |
| `-l`, `--list` | Input list file (domains/subdomains) | none |
| `--takeover` | Run takeover-only mode on provided hosts | `false` |
| `--update-fingerprints` | Update takeover fingerprint pack (and continue/exit) | `false` |
| `--passive` | Enable passive collection | `true` |
| `--bruteforce` | Enable bruteforce mode | `false` |
| `-w`, `--wordlist` | Bruteforce wordlist path | none |
| `--bruteforce-depth` | Recursive bruteforce label depth | `1` |
| `--bruteforce-max` | Max bruteforce candidates | `10000` |
| `--permutation` | Enable smart permutation expansion | `false` |
| `--permutation-depth` | Permutation recursion depth | `1` |
| `--permutation-max` | Max permutation candidates | `5000` |
| `-s`, `--sources` | Comma-separated source list | all |
| `-es`, `--exclude-sources` | Exclude source list | none |
| `--list-sources` | Print passive sources and exit | off |
| `--provider-config` | Provider env file path | `~/.config/subflare/providers.env` |
| `--no-banner` | Disable banner output | off |

### Passive runtime options

| Option | Description | Default |
|-------|-------------|---------|
| `--rate-limit` | Global source request rate (req/sec) | `0` (unlimited) |
| `--rls` | Per-source rate limits | none |
| `--source-timeout` | Source request timeout | `20s` |
| `--source-timeout-source` | Per-source timeout overrides | none |
| `--source-retries` | Retries per source | `2` |
| `--source-backoff` | Base retry backoff | `300ms` |
| `--source-max-backoff` | Max retry backoff | `5s` |
| `--cache-dir` | Passive cache directory | `~/.cache/subflare` |
| `--cache-ttl` | Passive cache TTL | `24h` |
| `--no-cache` | Disable passive cache | off |
| `--auto-tune` | Adaptive concurrency by timeout/error rate | off |

### DNS validation options

| Option | Description | Default |
|-------|-------------|---------|
| `-r`, `--resolvers` | Fast resolver list/file | built-in |
| `-tr`, `--trusted-resolvers` | Trusted resolver list/file | built-in |
| `-t`, `--threads` | DNS worker concurrency | `200` |
| `--dns-backend` | DNS backend (`standard` or `massdns`) | `standard` |
| `--massdns-path` | Path to massdns binary | `massdns` |
| `--rdns-expand` | Expand via reverse DNS of resolved IPs | `false` |
| `--rdns-limit` | Max reverse-DNS expansion candidates | `1000` |
| `--timeout` | Per-query DNS timeout | `3s` |
| `--retries` | DNS retries per host | `2` |
| `--wildcard-tests` | Random suffix checks for wildcard detect | `2` |

### Enrichment & takeover options

| Option | Description | Default |
|-------|-------------|---------|
| `--takeover` | Run takeover-only mode on provided hosts | `false` |
| `-l`, `--list` | Input list file for takeover-only target hosts | none |
| `--enrich-infra` | Enrich validated hosts with ASN/CDN hints | `false` |
| `--http-probe` | Probe validated hosts over HTTP/HTTPS | `false` |
| `--http-probe-timeout` | Timeout for HTTP probe requests | `5s` |
| `--http-probe-threads` | Concurrency for HTTP probing | `50` |
| `--takeover-check` | Run takeover signal checks | `false` |
| `--takeover-threads` | Concurrency for takeover checks | `25` |
| `--takeover-timeout` | Timeout for takeover checks | `5s` |

### Output & automation options

| Option | Description | Default |
|-------|-------------|---------|
| `-o`, `--output` | Save text output file | none |
| `--jsonl` | Save JSONL output file | none |
| `--silent` | Print only subdomains to stdout | off |
| `--verbose` | Show detailed source warnings | off |
| `--stdin` | Read domains from stdin | off |
| `--strict-io` | No banner/stats, stdout-only result mode | off |

### Monitor & webhook options

| Option | Description | Default |
|-------|-------------|---------|
| `--monitor-interval` | Monitor interval | `10m` |
| `--monitor-cycles` | Number of cycles (`0` infinite) | `0` |
| `--only-new` | Monitor mode stdout: print only newly discovered hosts | off |
| `--state-dir` | Snapshot state directory | tool default (falls back to `/tmp/subflare-state` when default is not writable) |
| `--webhook` | Generic webhook URL list | none |
| `--webhook-discord` | Discord webhook URL | none |
| `--webhook-slack` | Slack webhook URL | none |
| `--webhook-telegram-bot` | Telegram bot token | none |
| `--webhook-telegram-chat` | Telegram chat ID | none |
| `--webhook-timeout` | Webhook request timeout | `10s` |

---

## Passive Sources

### Standard + public sources

- alienvault
- anubis
- certspotter
- commoncrawl
- crtsh
- digitorus
- hackertarget
- leakix
- rapiddns
- riddler
- sitedossier
- threatcrowd
- threatminer
- waybackarchive

### API-driven enrichment sources

- censys
- chaos
- fofa
- github
- gitlab
- netlas
- securitytrails
- shodan
- virustotal
- whoisxmlapi
- zoomeyeapi

---

## Provider Keys

Default provider file path:

`~/.config/subflare/providers.env`

Custom path:

```bash
subflare -d example.com --provider-config /path/to/providers.env
```

Example:

```env
SHODAN_API_KEY=...
SECURITYTRAILS_API_KEY=...
VIRUSTOTAL_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
WHOISXMLAPI_API_KEY=...
CHAOS_API_KEY=...
FOFA_EMAIL=...
FOFA_KEY=...
ZOOMEYE_API_KEY=...
GITHUB_TOKEN=...
GITLAB_TOKEN=...
NETLAS_API_KEY=...
CERTSPOTTER_TOKEN=...
LEAKIX_API_KEY=...
ALIENVAULT_API_KEY=...
```

---

## Examples

Basic scan:

```bash
subflare -d hiddeninvestigations.net
```

Bruteforce + permutation depth tuning:

```bash
subflare -d hiddeninvestigations.net \
  --bruteforce -w words.txt \
  --bruteforce-depth 2 --bruteforce-max 20000 \
  --permutation --permutation-depth 2 --permutation-max 5000
```

MassDNS backend:

```bash
subflare -d hiddeninvestigations.net --dns-backend massdns --massdns-path /usr/bin/massdns
```

Reverse-DNS + HTTP probe + takeover checks:

```bash
subflare -d hiddeninvestigations.net --rdns-expand --http-probe --takeover-check
```

Infra enrichment + adaptive concurrency:

```bash
subflare -d hiddeninvestigations.net --enrich-infra --auto-tune
```

Takeover-only from file:

```bash
subflare --takeover -l subs.txt
```

Takeover-only from stdin:

```bash
cat sub.txt | subflare --takeover
```

Combine list file + stdin in automation mode:

```bash
subflare --stdin --strict-io --no-banner -l domain.txt
```

Update takeover fingerprints:

```bash
subflare --update-fingerprints
```

Save text + JSONL:

```bash
subflare -d hiddeninvestigations.net -o results.txt --jsonl results.jsonl
```

Show detailed source errors:

```bash
subflare -d hiddeninvestigations.net --verbose
```

Diff old and new runs:

```bash
subflare diff --old old.txt --new new.txt --show all
```

Monitor with Discord alerts:

```bash
subflare monitor -d hiddeninvestigations.net \
  --monitor-interval 30m \
  --state-dir /tmp/subflare-state \
  --webhook-discord 'https://discord.com/api/webhooks/...'
```

Monitor pipelines with only-new stdout:

```bash
subflare monitor -d hiddeninvestigations.net --only-new --strict-io
```

---

## Takeover Check Behavior

`--takeover-check` performs **signal-based takeover checks** on validated hosts:

- Matches known CNAME provider fingerprints.
- Flags dangling CNAME targets only when DNS errors indicate hard non-existence (for example NXDOMAIN / no such host).
- Applies provider-aware HTTP fingerprint checks using response status + content indicators.

Current built-in provider rules include:

- GitHub Pages
- Heroku
- ReadTheDocs
- Pantheon
- AWS S3 website/bucket endpoints
- Azure App Service
- Vercel
- Surge

`--update-fingerprints` refreshes the local fingerprint pack at:

`~/.config/subflare/takeover-fingerprints.json`

Scan summary now reports:

- `takeover checked`: how many hosts were evaluated for takeover signals.
- `takeover signals`: how many hosts matched takeover indicators.

When `--takeover-check` is enabled, terminal output also prints a dedicated **Takeover Assessment** section:

- Lists only hosts with takeover possibility signals (`[TAKEOVER][HIGH|MEDIUM|LOW] ...`)
- Prints a clear no-findings message (`no luck`) when no takeover possibility is detected
- Does not change the normal subdomain host result output format

This output is a **high-value triage signal**, not a final vulnerability verdict. Always manually verify takeover candidates before reporting.

`--takeover` runs takeover checks directly on provided host lists (`-l`, `--stdin`, or piped stdin) without running passive/bruteforce discovery.

With `--takeover --strict-io`, stdout contains only takeover-positive hosts.

---

## JSONL Output

When `--jsonl` is used, each line contains one validated record with fields such as:

- `host`, `domain`
- `sources`, `source_count`, `duplicates_merged`
- `confidence`, `first_seen`
- `a` (A records), `cname`
- `infra_asn`, `infra_org`, `infra_cdn`
- `takeover_confidence`
- `validated`

---

## Credits & Acknowledgements

- **[Hidden Investigations](https://hiddeninvestigations.net/)** – Cybersecurity Research & Vulnerability Disclosure.
- **[@sakibulalikhan](https://github.com/sakibulalikhan)** – project author.
- Community recon tooling ecosystem for inspiration and benchmarking direction.

---

## License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

📬 Contact: [hi@hiddeninvestigations.net](mailto:hi@hiddeninvestigations.net)
