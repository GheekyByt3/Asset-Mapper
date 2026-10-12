# Asset-Mapper

Passive external host discovery that produces an Excel workbook your client can use to answer one question: **"is this ours, and is it in scope?"**

Feed it a list of root domains. It gathers subdomains from several sources, resolves every hostname itself (A records), enriches each IP with ASN and cloud/CDN data, and writes an `.xlsx` with scope dropdowns the client can fill in.

> **Authorized use only.** Run this only against domains you are authorized to assess. Discovery is passive, but the DNS resolution step does generate lookups for every hostname found.

## How it works

1. **Collect** hostnames from each enabled source. A missing or failing source is skipped and reported, never silently ignored.
2. **Resolve** every hostname against public resolvers (default `1.1.1.1`, `8.8.8.8`). Sources never supply IPs; resolution is done fresh so results are consistent.
3. **Enrich** each public IP with ASN, network range and country (Team Cymru DNS lookup) and flag cloud/CDN providers.
4. **Export** to Excel.

| Source | Needs | Notes |
|---|---|---|
| crt.sh | nothing | Certificate transparency. Free but occasionally returns 502; the tool retries with backoff. |
| subfinder | [subfinder](https://github.com/projectdiscovery/subfinder) installed | Found on `PATH`, `~/go/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, or via `--subfinder-path`. Add provider keys in subfinder's own config for better coverage. |
| DNSDumpster | API key | Free tier is capped at about 50 records per domain. Skipped if no key. |

## Install

```bash
git clone https://github.com/GheekyByt3/Asset-Mapper.git Asset-Mapper && cd Asset-Mapper
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10+.

## Usage

```bash
# domains.txt: one root domain per line
python3 asset_mapper.py domains.txt -o client_assets.xlsx

# choose sources
python3 asset_mapper.py domains.txt --sources crtsh,subfinder

# subfinder not on PATH
python3 asset_mapper.py domains.txt --subfinder-path /path/to/subfinder

# DNSDumpster key (prefer the env var; -k shows up in the process list and shell history)
export DNSDUMPSTER_API_KEY=...
python3 asset_mapper.py domains.txt
```

| Option | Default | Purpose |
|---|---|---|
| `-o, --output` | `asset_mapper.xlsx` | Output workbook |
| `--sources` | `dnsdumpster,crtsh,subfinder` | Comma-separated subset |
| `-k, --api-key` | `$DNSDUMPSTER_API_KEY` | DNSDumpster key |
| `--subfinder-path` | auto-detect | Path to subfinder binary |
| `--resolvers` | `1.1.1.1,8.8.8.8` | DNS resolvers used for resolution and ASN lookups |
| `--threads` | `20` | Concurrent lookups |
| `--no-asn` | off | Skip ASN/cloud enrichment |

See `examples/domains.example.txt` for the input format.

## Workbook

| Sheet | Contents |
|---|---|
| **Summary** | Per-domain counts: hosts found by each source, resolved, unresolved, unique IPs |
| **All Records** | One row per host and IP: root domain, hostname, IP, sources, cloud/CDN, ASN, network, country, flags. The first column, **Scope Validation Status** (light orange, dropdown: In Scope / Out of Scope / Unsure), and the last column, **Notes** (light orange), are left blank for the client to fill in |
| **Unique IPs** | IPs with all hostnames pointing at them, same scope dropdown. Best sheet for confirming IP ownership |
| **Unresolved** | Hostnames found but not resolving (stale DNS, AAAA-only, dead records) with DNS status |
| **Source Status** | Per-source result or error. Check this before trusting coverage |

### Flags

- `SINGLE-SOURCE`: only one source found this host; worth a second look.
- `WILDCARD`: the domain has wildcard DNS and this host only resolves to the wildcard IPs, so it may not be a real asset.
- `NON-PUBLIC IP`: resolves to a private address. Often a leaked internal name; raise with the client.

## Limitations

- IPv4 A records only. Hosts with only AAAA records appear under **Unresolved** (`NOANSWER`).
- Passive data does not prove ownership. Shared hosting and CDN addresses appear in results; the **Cloud/CDN** column helps spot them, and the client makes the scope call.
- The cloud/CDN flag is a keyword match on the ASN name (`CLOUD_KEYWORDS` in `asset_mapper.py`). Extend it as needed.
- Source coverage varies by domain. Always check **Source Status** for failed or skipped sources.
- Spreadsheet cells beginning with `= + - @` are prefixed with `'` so hostile DNS data cannot become Excel formulas.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q                 # includes a few live DNS tests
SKIP_LIVE=1 pytest -q     # offline
```

Adding a source: write `src_<name>(domain, ctx)` returning `(set_of_hostnames, error_or_None)`, filter results with `normalize_host(name, domain)`, and register it in `SOURCES`.

## Ideas / roadmap

Amass, Censys and Shodan sources; reverse-DNS sweeps of known client ranges; a per-source "unique finds" summary.
