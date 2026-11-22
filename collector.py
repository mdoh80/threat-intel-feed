"""Fetch, normalize, and persist threat-intelligence feeds for the static site."""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "intelligence.json"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVSS_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60
NVD_REQUEST_INTERVAL_SECONDS = 0.7
NVD_REQUEST_INTERVAL_WITHOUT_KEY_SECONDS = 6.0
NVD_MAX_REQUESTS_WITH_KEY = 20
NVD_MAX_REQUESTS_WITHOUT_KEY = 5
SOURCE_URLS = {
    "cisa_news": "https://www.cisa.gov/news.xml",
    "cisa_advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
    "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_datetime(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().replace(" UTC", "+00:00")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_url(value: Any) -> str | None:
    if not value:
        return None
    try:
        parsed = urllib.parse.urlparse(str(value).strip())
    except ValueError:
        return None
    return str(value).strip() if parsed.scheme in {"http", "https"} and parsed.netloc else None


def cves(text: str) -> list[str]:
    return sorted({match.upper() for match in CVE_RE.findall(text or "")})


def text_value(element: ET.Element | None) -> str:
    return " ".join("".join(element.itertext()).split()) if element is not None else ""


def parse_rss(payload: bytes, source: str) -> list[dict[str, Any]]:
    root = ET.fromstring(payload)
    entries = []
    for item in root.findall(".//item"):
        title = text_value(item.find("title"))
        summary = text_value(item.find("description"))
        link = safe_url(text_value(item.find("link")))
        published = parse_datetime(text_value(item.find("pubDate")) or text_value(item.find("published")))
        combined = f"{title} {summary}"
        entries.append({
            "id": link or f"{source}:{title}:{published}",
            "kind": "advisory" if source == "cisa_advisories" else "news",
            "source": source,
            "title": title or "Untitled item",
            "summary": summary,
            "published": published,
            "url": link,
            "cves": cves(combined),
        })
    return dedupe(entries, "id")


def parse_kev(payload: bytes) -> list[dict[str, Any]]:
    raw = json.loads(payload)
    entries = []
    for item in raw.get("vulnerabilities", []):
        cve = str(item.get("cveID", "")).upper()
        if not cve:
            continue
        entries.append({
            "id": cve,
            "source": "cisa_kev",
            "cve": cve,
            "title": item.get("vulnerabilityName") or cve,
            "vendor": item.get("vendorProject") or "Unknown",
            "product": item.get("product") or "Unknown",
            "description": item.get("shortDescription") or "",
            "required_action": item.get("requiredAction") or "",
            "date_added": parse_datetime(item.get("dateAdded")),
            "due_date": parse_datetime(item.get("dueDate")),
            "ransomware_use": item.get("knownRansomwareCampaignUse") or "Unknown",
            "cvss_score": None,
            "cvss_version": None,
            "cvss_severity": "Unavailable",
            "cvss_source": None,
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={urllib.parse.quote(cve)}",
        })
    return dedupe(entries, "id")


def cvss_severity(score: Any) -> str:
    """Classify a validated CVSS base score using the standard ranges."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "Unavailable"
    if not 0 <= value <= 10:
        return "Unavailable"
    if value == 0:
        return "None"
    if value < 4:
        return "Low"
    if value < 7:
        return "Medium"
    if value < 9:
        return "High"
    return "Critical"


def extract_cvss(vulnerability: dict[str, Any]) -> dict[str, Any] | None:
    """Select the highest-priority NVD CVSS metric from one CVE response."""
    metrics = vulnerability.get("cve", {}).get("metrics", {})
    for version, key in (("4.0", "cvssMetricV40"), ("3.1", "cvssMetricV31"), ("3.0", "cvssMetricV30"), ("2.0", "cvssMetricV2")):
        candidates = metrics.get(key) or []
        ordered = sorted(candidates, key=lambda metric: 0 if metric.get("type") == "Primary" else 1)
        for metric in ordered:
            cvss_data = metric.get("cvssData") or {}
            score = cvss_data.get("baseScore")
            severity = cvss_severity(score)
            if severity != "Unavailable":
                value = float(score)
                return {
                    "score": round(value, 1),
                    "version": version,
                    "severity": severity,
                    "source": "NVD",
                }
    return None


def cache_entry_fresh(entry: dict[str, Any], now: datetime | None = None) -> bool:
    fetched_at = parse_datetime(entry.get("fetched_at"))
    if not fetched_at:
        return False
    parsed = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    return (current - parsed).total_seconds() < CVSS_CACHE_TTL_SECONDS


def apply_cvss(record: dict[str, Any], entry: dict[str, Any]) -> None:
    record["cvss_score"] = entry.get("score")
    record["cvss_version"] = entry.get("version")
    record["cvss_severity"] = entry.get("severity") or "Unavailable"
    record["cvss_source"] = entry.get("source")


def fetch_cvss(cve: str, *, api_key: str | None, fetcher: Callable[..., bytes]) -> dict[str, Any] | None:
    headers = {"apiKey": api_key} if api_key else None
    query = urllib.parse.urlencode({"cveId": cve})
    raw = json.loads(fetcher(f"{NVD_CVE_URL}?{query}", headers=headers))
    vulnerabilities = raw.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    return extract_cvss(vulnerabilities[0])


def enrich_kev_cvss(
    data: dict[str, Any],
    *,
    api_key: str | None = None,
    fetcher: Callable[..., bytes] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> None:
    """Best-effort NVD enrichment with a persistent, expiring per-CVE cache."""
    cache = data.setdefault("cvss_cache", {})
    lookup = fetcher or fetch
    sleep = sleeper or time.sleep
    now = datetime.now(timezone.utc)
    pending: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in data.get("kev", []):
        cve = record.get("cve")
        if not cve or cve in seen:
            continue
        seen.add(cve)
        cached = cache.get(cve)
        if isinstance(cached, dict):
            apply_cvss(record, cached)
        if not isinstance(cached, dict) or not cache_entry_fresh(cached, now):
            pending.append(record)

    max_requests = NVD_MAX_REQUESTS_WITH_KEY if api_key else NVD_MAX_REQUESTS_WITHOUT_KEY
    interval = NVD_REQUEST_INTERVAL_SECONDS if api_key else NVD_REQUEST_INTERVAL_WITHOUT_KEY_SECONDS
    for index, record in enumerate(pending[:max_requests]):
        if index:
            sleep(interval)
        cve = record["cve"]
        try:
            result = fetch_cvss(cve, api_key=api_key, fetcher=lookup)
        except Exception:
            continue
        entry = {
            **(result or {"score": None, "version": None, "severity": "Unavailable", "source": "NVD"}),
            "fetched_at": now_iso(),
        }
        cache[cve] = entry
        apply_cvss(record, entry)


def parse_urlhaus(payload: bytes) -> list[dict[str, Any]]:
    raw = json.loads(payload)
    entries = []
    for item in raw.get("urls", []):
        url = safe_url(item.get("url"))
        if not url:
            continue
        entries.append({
            "id": str(item.get("id") or url),
            "source": "urlhaus",
            "ioc": url,
            "ioc_type": "url",
            "host": item.get("host") or urllib.parse.urlparse(url).hostname or "Unknown",
            "status": item.get("url_status") or "unknown",
            "tags": item.get("tags") if isinstance(item.get("tags"), list) else [],
            "first_seen": parse_datetime(item.get("date_added")),
            "url": safe_url(item.get("urlhaus_reference")),
        })
    return dedupe(entries, "id")


def parse_threatfox(payload: bytes) -> list[dict[str, Any]]:
    raw = json.loads(payload)
    if raw.get("query_status") in {"no_results", "no_result"}:
        return []
    if raw.get("query_status") != "ok":
        raise ValueError(f"ThreatFox query status: {raw.get('query_status', 'unknown')}")
    entries = []
    for item in raw.get("data") or []:
        ioc = str(item.get("ioc") or "").strip()
        if not ioc:
            continue
        entries.append({
            "id": str(item.get("id") or ioc),
            "source": "threatfox",
            "ioc": ioc,
            "ioc_type": item.get("ioc_type") or "Unknown",
            "threat_type": item.get("threat_type") or "Unknown",
            "malware": item.get("malware_printable") or item.get("malware") or "Unknown",
            "confidence": item.get("confidence_level"),
            "first_seen": parse_datetime(item.get("first_seen")),
            "url": safe_url(item.get("reference")),
        })
    return dedupe(entries, "id")


def dedupe(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result = []
    for item in items:
        identity = str(item.get(key) or "")
        if identity and identity not in seen:
            seen.add(identity)
            result.append(item)
    return result


def fetch(url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method="POST" if body else "GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def default_data() -> dict[str, Any]:
    return {"generated_at": None, "sources": {}, "cvss_cache": {}, "news": [], "advisories": [], "kev": [], "urlhaus": [], "threatfox": []}


def load_data() -> dict[str, Any]:
    if not DATA_PATH.exists():
        return default_data()
    try:
        loaded = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        base = default_data()
        base.update(loaded)
        return base
    except (OSError, json.JSONDecodeError):
        return default_data()


def collect_source(data: dict[str, Any], name: str, parser: Callable[[bytes], list[dict[str, Any]]], *, headers: dict[str, str] | None = None, body: bytes | None = None) -> None:
    attempted = now_iso()
    try:
        records = parser(fetch(SOURCE_URLS[name], headers=headers, body=body))
        target = {
            "cisa_news": "news",
            "cisa_advisories": "advisories",
            "cisa_kev": "kev",
        }.get(name, name)
        data[target] = records
        data.setdefault("sources", {})[name] = {"status": "healthy", "last_success": attempted, "last_attempt": attempted, "error": None, "url": SOURCE_URLS[name]}
    except Exception as exc:  # preserve last-known-good data for any upstream failure
        prior = data.setdefault("sources", {}).get(name, {})
        data["sources"][name] = {**prior, "status": "stale" if prior.get("last_success") else "error", "last_attempt": attempted, "error": str(exc)[:240], "url": SOURCE_URLS[name]}


def mark_not_configured(data: dict[str, Any], name: str, message: str) -> None:
    prior = data.setdefault("sources", {}).get(name, {})
    data["sources"][name] = {**prior, "status": "not_configured", "last_attempt": now_iso(), "error": message, "url": SOURCE_URLS[name]}


def apply_kev_matches(data: dict[str, Any]) -> None:
    """Annotate CISA feed items with KEV CVEs without changing their source text."""
    kev_ids = {item["cve"] for item in data.get("kev", []) if item.get("cve")}
    for item in data.get("news", []) + data.get("advisories", []):
        item["kev_matches"] = sorted(set(item.get("cves", [])) & kev_ids)


def main() -> int:
    data = load_data()
    collect_source(data, "cisa_news", lambda payload: parse_rss(payload, "cisa_news"))
    collect_source(data, "cisa_advisories", lambda payload: parse_rss(payload, "cisa_advisories"))
    collect_source(data, "cisa_kev", parse_kev)
    enrich_kev_cvss(data, api_key=os.environ.get("NVD_API_KEY"))

    urlhaus_key = os.environ.get("URLHAUS_AUTH_KEY")
    if urlhaus_key:
        collect_source(data, "urlhaus", parse_urlhaus, headers={"Auth-Key": urlhaus_key})
    else:
        mark_not_configured(data, "urlhaus", "URLHAUS_AUTH_KEY is not configured")

    threatfox_key = os.environ.get("THREATFOX_AUTH_KEY")
    if threatfox_key:
        collect_source(data, "threatfox", parse_threatfox, headers={"Auth-Key": threatfox_key, "Content-Type": "application/json"}, body=json.dumps({"query": "get_iocs", "days": 3}).encode())
    else:
        mark_not_configured(data, "threatfox", "THREATFOX_AUTH_KEY is not configured")

    apply_kev_matches(data)
    data["generated_at"] = now_iso()
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATA_PATH.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
