# 🐉 Dragon Scanner

A **passive subdomain enumeration** tool written in Go. It queries free sources in parallel, filters results to the target's scope, and saves a unique, sorted list. No API key is required.

## Sources

All sources are free. Sources marked *confirmed* returned results in a real scan.

| Source | Type | Status |
|---|---|---|
| crt.sh | Certificate Transparency | confirmed |
| CertSpotter | Certificate Transparency | confirmed (optional key) |
| AlienVault OTX | URLs + passive DNS | confirmed |
| URLScan.io | Scanned pages | confirmed (optional key) |
| RapidDNS | DNS database | confirmed |
| DNSRepo | DNS database | confirmed |
| Assetfinder | External tool (optional) | confirmed |
| Wayback Machine (CDX) | Web archive | testing |
| Subfinder | External tool (optional) | testing |

### Optional API keys

These sources work without a key; a key only raises the rate limit.

| Source | Variable |
|---|---|
| CertSpotter | `CERTSPOTTER_API_KEY` |
| URLScan.io | `URLSCAN_API_KEY` |

```bash
export CERTSPOTTER_API_KEY="your_key"
```

Add the line to `~/.bashrc` or `~/.zshrc` to make it permanent. Never hardcode keys.

## Installation

Requires [Go](https://go.dev/dl/).

### Install

```bash
go install github.com/codecraft123-j/dragon@v1.2.0
```

If it fails with `verifying module ... 404 Not Found` (the Go checksum database has not indexed the release yet), fetch it straight from GitHub:

```bash
GOPROXY=direct GONOSUMDB=github.com/codecraft123-j/dragon go install github.com/codecraft123-j/dragon@v1.2.0
```

### Alternative: build from source

```bash
git clone https://github.com/codecraft123-j/dragon.git
cd dragon
go install .
```

The binary is placed in `~/go/bin/dragon`. Check the version with `dragon -ls`; the banner should show `v1.2.0` or newer.

### PATH

If `~/go/bin` is not in your PATH:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
hash -r
```

### Optional dependencies

`subfinder` and `assetfinder` must be in your PATH to be used. If they are missing, Dragon reports it and continues with the other sources.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
```

## Usage

```bash
# Single target
dragon -u example.com

# List of targets
dragon -l targets.txt

# Custom output file, longer timeout, no banner
dragon -u example.com -o result.txt -t 300s -silent

# List the sources
dragon -ls

# Show why a source failed
dragon -u example.com -v
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `-u` | Single target (e.g. `example.com`) | — |
| `-l` | File with targets, one per line | — |
| `-o` | Output file | `subdomains.txt` |
| `-t` | Timeout per target | `90s` |
| `-silent` | Hide the banner | `false` |
| `-ls` | List the sources | `false` |
| `-strict` | Also drop hosts shaped like `ww<N>.<subdomain>.target` (noisy pattern) | `false` |
| `-v` | Show why each failed source failed | `false` |

Logs and progress go to `stderr`; results go to the output file, so it works in pipelines:

```bash
dragon -u example.com -silent && cat subdomains.txt | httpx -silent
```

## How it works

1. Each source runs in parallel (goroutines).
2. Results are normalized: lowercase, no `*.` prefix, no duplicates.
3. Only hosts inside the target scope are kept (`target.com` or `*.target.com`). Scraping artifacts are dropped: IP-like fragments (`192.0.2.44www.target.com`), target text glued to other characters (`target.commail.target.com`), and empty or oversized labels.
4. The final list is sorted and saved to a file.
5. If a source fails (rate limit, timeout, service down), Dragon prints a warning and continues with the rest.

Free sources change or go offline over time. Use `-v` to see which ones are failing.

## Legal notice

Use only against targets you are **authorized** to test, such as in-scope bug bounty programs or your own assets. The author is not responsible for misuse of this tool.

## Author

**laftman** — [@codecraft123-j](https://github.com/codecraft123-j)
