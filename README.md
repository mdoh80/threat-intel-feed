# Threat Intel Feed

Threat Intel Feed is a static GitHub Pages signal console for open-source threat intelligence. It collects CISA news, CISA cybersecurity advisories, CISA Known Exploited Vulnerabilities (KEV), recent URLhaus malware URLs, and recent ThreatFox malware-related IOCs. The visual language follows the supplied Figma “Signal Console” reference: dark SOC panels, green operational accents, monospace telemetry, and a moving KEV ticker.

## Architecture

GitHub Actions runs `scripts/collect.py`, which uses Python’s standard library to fetch and normalize upstream RSS/JSON. The generated `data/intelligence.json` is committed back to the repository so a failed scheduled run cannot erase the previous source records. GitHub Pages serves `index.html`, `styles.css`, `app.js`, and the generated data as a static site.

The normalized records include source identifiers, UTC timestamps, original links, CVE extraction, and CISA-news/advisory-to-KEV cross-references. The frontend renders untrusted values with `textContent`, validates external HTTP(S) links, and never visits IOC URLs.

## Sources and attribution

- [CISA news RSS](https://www.cisa.gov/news.xml)
- [CISA cybersecurity advisories RSS](https://www.cisa.gov/cybersecurity-advisories/all.xml)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [URLhaus Community API](https://urlhaus-api.abuse.ch/)
- [ThreatFox Community API](https://threatfox.abuse.ch/api)

URLhaus and ThreatFox are abuse.ch community services. Their free APIs are subject to fair-use principles and provider terms. ThreatFox IOCs are not evidence that an organization is compromised. A CVE’s absence from the CISA KEV catalog does not prove that it has not been exploited. `Unknown` ransomware use remains `Unknown`; it is never converted to “No”.

## GitHub setup

1. Enable GitHub Pages with **GitHub Actions** as the source.
2. Add the repository secrets below under **Settings → Secrets and variables → Actions**.
3. Merge the workflows from this feature branch through the normal review process. The collector runs every 15 minutes and can also be started with **Actions → Collect threat intelligence → Run workflow**. The CISA KEV endpoint is collected on the same schedule; the source timestamp is the actual successful fetch time.

| Secret | Required | Purpose |
| --- | --- | --- |
| `THREATFOX_AUTH_KEY` | Recommended | Auth-Key required by the ThreatFox Community API. |
| `URLHAUS_AUTH_KEY` | Recommended | Auth-Key required by the URLhaus automated API. |

If either secret is absent, the dashboard continues to work and marks that source **NOT CONFIGURED**. Secrets are passed only as workflow environment variables and request headers; they are not written to JSON, frontend code, logs, or commits.

## Local development

No package installation is required. Serve the repository root over HTTP so the browser can fetch JSON:

```bash
python3 -m http.server 8000
```

Open `http://localhost:8000/`. To collect locally, set the optional environment variables and run:

```bash
THREATFOX_AUTH_KEY=... URLHAUS_AUTH_KEY=... python3 scripts/collect.py
```

Do not open or download IOC URLs. The collector only downloads provider API responses.

## Tests and validation

Unit tests use local fixtures and mocked HTTP calls:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile collector.py scripts/collect.py
git diff --check
```

The test suite covers RSS and JSON parsing, CVE extraction, deduplication, safe URL handling, secret non-persistence, and preservation of last-known-good source data after a failed fetch.

## Design and data limitations

The interface is responsive and intended for GitHub Pages’ repository subpath; data is loaded using a document-relative URL. Counts are calculated from retained records, and empty or unavailable feeds show explicit states instead of synthetic activity. The activity bars count real timestamps from the latest retained records within the preceding 24 hours; they do not represent a global compromise map or incident count.

Scheduled GitHub Actions are best-effort rather than exact timers. The source-health cards show the actual last successful fetch, failed attempt, and retained-data state. The Pages workflow is configured for `https://mdoh80.github.io/threat-intel-feed/` after the repository is published.

## Security considerations

Feed content is untrusted. The frontend uses DOM text nodes rather than HTML injection and adds `noopener noreferrer` to external source links. It does not automatically request, resolve, or execute IOC URLs. Review provider terms, rate limits, and retention policies before changing collection volume or cadence.
