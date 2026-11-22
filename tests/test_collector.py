"""Unit tests for source parsing, normalization, and failure-safe persistence."""

import json
import unittest
from unittest.mock import patch

import collector


class CollectorTests(unittest.TestCase):
    def test_rss_parsing_extracts_cves_and_deduplicates(self):
        payload = b"""<rss><channel><item><title>Fix CVE-2024-12345</title><description><![CDATA[<p>Summary with <strong>formatting</strong>.</p>]]></description><pubDate>Wed, 20 Nov 2024 12:00:00 GMT</pubDate><link>https://example.test/a</link></item><item><title>Fix CVE-2024-12345</title><link>https://example.test/a</link></item></channel></rss>"""
        result = collector.parse_rss(payload, "cisa_advisories")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cves"], ["CVE-2024-12345"])
        self.assertEqual(result[0]["kind"], "advisory")
        self.assertEqual(result[0]["summary"], "<p>Summary with <strong>formatting</strong>.</p>")

    def test_kev_parsing_normalizes_unknown_ransomware(self):
        payload = json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-1", "vulnerabilityName": "Name", "vendorProject": "Vendor", "product": "Product", "dateAdded": "2024-01-01", "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Unknown"}]}).encode()
        item = collector.parse_kev(payload)[0]
        self.assertEqual(item["cve"], "CVE-2024-1")
        self.assertEqual(item["ransomware_use"], "Unknown")

    def test_urlhaus_parsing_ignores_invalid_urls(self):
        payload = json.dumps({"urls": [{"id": "1", "url": "https://malware.test/a", "host": "malware.test", "url_status": "online", "date_added": "2024-01-01 01:02:03 UTC", "tags": ["loader"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}, {"id": "2", "url": "javascript:alert(1)"}]}).encode()
        result = collector.parse_urlhaus(payload)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ioc_type"], "url")

    def test_threatfox_parsing(self):
        payload = json.dumps({"query_status": "ok", "data": [{"id": 1, "ioc": "evil.test", "ioc_type": "domain", "threat_type": "botnet_cc", "malware_printable": "Example", "confidence_level": 75, "first_seen": "2024-01-01 01:02:03 UTC"}]}).encode()
        item = collector.parse_threatfox(payload)[0]
        self.assertEqual(item["malware"], "Example")
        self.assertEqual(item["confidence"], 75)

    def test_empty_source_response_is_a_successful_empty_collection(self):
        self.assertEqual(collector.parse_rss(b"<rss><channel /></rss>", "cisa_news"), [])
        self.assertEqual(collector.parse_urlhaus(b'{"query_status":"no_results","urls":[]}'), [])
        self.assertEqual(collector.parse_threatfox(b'{"query_status":"no_results"}'), [])

    def test_failed_source_with_previous_success_is_stale(self):
        data = collector.default_data()
        data["news"] = [{"id": "old"}]
        data["sources"]["cisa_news"] = {"last_success": "2024-01-01T00:00:00Z", "status": "healthy"}
        with patch.object(collector, "fetch", side_effect=OSError("temporary failure")):
            collector.collect_source(data, "cisa_news", lambda payload: collector.parse_rss(payload, "cisa_news"))
        self.assertEqual(data["news"], [{"id": "old"}])
        self.assertEqual(data["sources"]["cisa_news"]["status"], "stale")

    def test_failed_source_without_previous_success_is_error(self):
        data = collector.default_data()
        data["news"] = [{"id": "old"}]
        with patch.object(collector, "fetch", side_effect=OSError("temporary failure")):
            collector.collect_source(data, "cisa_news", lambda payload: collector.parse_rss(payload, "cisa_news"))
        self.assertEqual(data["news"], [{"id": "old"}])
        self.assertEqual(data["sources"]["cisa_news"]["status"], "error")

    def test_successful_kev_collection_uses_kev_data_key(self):
        data = collector.default_data()
        payload = json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}).encode()
        with patch.object(collector, "fetch", return_value=payload):
            collector.collect_source(data, "cisa_kev", collector.parse_kev)

        self.assertEqual([item["cve"] for item in data["kev"]], ["CVE-2024-12345"])
        self.assertNotIn("cisa_kev", data)
        self.assertEqual(data["sources"]["cisa_kev"]["status"], "healthy")

    def test_collected_kev_records_annotate_matching_news_and_advisories(self):
        data = collector.default_data()
        payload = json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}).encode()
        data["news"] = [{"cves": ["CVE-2024-12345", "CVE-2024-99999"]}]
        data["advisories"] = [{"cves": ["CVE-2024-99999"]}]
        with patch.object(collector, "fetch", return_value=payload):
            collector.collect_source(data, "cisa_kev", collector.parse_kev)

        collector.apply_kev_matches(data)
        self.assertEqual(data["news"][0]["kev_matches"], ["CVE-2024-12345"])
        self.assertEqual(data["advisories"][0]["kev_matches"], [])

    def test_failed_kev_collection_preserves_data_and_marks_source_stale(self):
        data = collector.default_data()
        data["kev"] = [{"cve": "CVE-2024-12345"}]
        data["sources"]["cisa_kev"] = {
            "last_success": "2024-01-01T00:00:00Z",
            "status": "healthy",
        }
        with patch.object(collector, "fetch", side_effect=OSError("temporary failure")):
            collector.collect_source(data, "cisa_kev", collector.parse_kev)

        self.assertEqual(data["kev"], [{"cve": "CVE-2024-12345"}])
        self.assertEqual(data["sources"]["cisa_kev"]["status"], "stale")
        self.assertIn("last_attempt", data["sources"]["cisa_kev"])

    def test_secret_is_only_used_as_header(self):
        data = collector.default_data()
        with patch.object(collector, "fetch", return_value=b'{"query_status":"ok","data":[]}') as fetch:
            collector.collect_source(data, "threatfox", collector.parse_threatfox, headers={"Auth-Key": "secret"}, body=b"{}")
        self.assertNotIn("secret", json.dumps(data))
        self.assertEqual(fetch.call_args.kwargs["headers"]["Auth-Key"], "secret")

    def test_kev_cross_reference_marks_only_catalog_matches(self):
        data = collector.default_data()
        data["kev"] = [{"cve": "CVE-2024-12345"}]
        data["news"] = [{"cves": ["CVE-2024-12345", "CVE-2024-99999"]}]
        collector.apply_kev_matches(data)
        self.assertEqual(data["news"][0]["kev_matches"], ["CVE-2024-12345"])


if __name__ == "__main__":
    unittest.main()
