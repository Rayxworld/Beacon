"""
Comprehensive deterministic unit tests for Beacon research pipeline.
Covers domain normalization, CT parsing & error handling, DNS provenance,
SPF/DMARC parsing, dataset building, anonymization, and statistical calculations.
Zero external network dependencies.
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from collectors.domain_utils import normalize_domain, get_registrable_domain, is_same_registrable_domain
from collectors.crtsh_collector import collect_domain_domains_detailed, _certificate_domains
from collectors.dns_security_collector import parse_spf, parse_dmarc, query_record_type
from collectors.research_dataset import domain_hash, _measure, summarize
from research.analyze_study import wilson_score_interval, kruskal_wallis, chi_square_2x2


class TestDomainNormalization(unittest.TestCase):
    def test_standard_domains(self):
        self.assertEqual(normalize_domain("example.com"), "example.com")
        self.assertEqual(normalize_domain("HTTPS://WWW.EXAMPLE.COM/path"), "example.com")
        self.assertEqual(normalize_domain("sub.example.com"), "sub.example.com")
        self.assertEqual(normalize_domain("*.wildcard.example.com"), "wildcard.example.com")

    def test_african_ccslds(self):
        self.assertEqual(normalize_domain("https://unilag.edu.ng/"), "unilag.edu.ng")
        self.assertEqual(normalize_domain("crdbbank.co.tz"), "crdbbank.co.tz")
        self.assertEqual(normalize_domain("gov.za"), "gov.za")
        self.assertEqual(normalize_domain("uonbi.ac.ke"), "uonbi.ac.ke")

    def test_registrable_domain_resolution(self):
        self.assertEqual(get_registrable_domain("mail.unilag.edu.ng"), "unilag.edu.ng")
        self.assertEqual(get_registrable_domain("unilag.edu.ng"), "unilag.edu.ng")
        self.assertEqual(get_registrable_domain("portal.crdbbank.co.tz"), "crdbbank.co.tz")
        self.assertEqual(get_registrable_domain("sub.domain.gov.za"), "domain.gov.za")
        self.assertEqual(get_registrable_domain("vpn.ug.edu.gh"), "ug.edu.gh")
        self.assertEqual(get_registrable_domain("app.example.com"), "example.com")

    def test_is_same_registrable_domain(self):
        self.assertTrue(is_same_registrable_domain("mail.unilag.edu.ng", "unilag.edu.ng"))
        self.assertTrue(is_same_registrable_domain("mx1.unilag.edu.ng", "mx2.unilag.edu.ng"))
        # Unrelated domains sharing ccSLD should NOT match
        self.assertFalse(is_same_registrable_domain("unilag.edu.ng", "ui.edu.ng"))
        self.assertFalse(is_same_registrable_domain("crdbbank.co.tz", "vodacom.co.tz"))

    def test_malformed_domains(self):
        with self.assertRaises(ValueError):
            normalize_domain("")
        with self.assertRaises(ValueError):
            normalize_domain("invalid domain with spaces")
        with self.assertRaises(ValueError):
            normalize_domain("singlelabel")


class TestCertificateTransparencyCollector(unittest.TestCase):
    def test_parse_certificate_domains(self):
        mock_response = [
            {"name_value": "example.com\n*.sub.example.com"},
            {"name_value": "admin.example.com"},
            {"name_value": "unrelated.org"},
        ]
        result = _certificate_domains(mock_response, "example.com")
        self.assertIn("example.com", result)
        self.assertIn("sub.example.com", result)
        self.assertIn("admin.example.com", result)
        self.assertNotIn("unrelated.org", result)

    @patch("requests.get")
    def test_crtsh_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "api.example.com"},
            {"name_value": "vpn.example.com"},
        ]
        mock_get.return_value = mock_resp

        res = collect_domain_domains_detailed("example.com", max_retries=1)
        self.assertEqual(res["certificate_query_status"], "success")
        self.assertTrue(res["certificate_source_available"])
        self.assertFalse(res["fallback_used"])
        self.assertEqual(res["certificate_result_count"], 2)
        self.assertIn("api.example.com", res["domains"])
        self.assertIn("example.com", res["domains"])

    @patch("requests.get")
    def test_crtsh_single_legitimate_result(self, mock_get):
        # A single certificate name MUST NOT be marked as source unavailable
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"name_value": "example.com"}]
        mock_get.return_value = mock_resp

        res = collect_domain_domains_detailed("example.com", max_retries=1)
        self.assertEqual(res["certificate_query_status"], "success")
        self.assertTrue(res["certificate_source_available"])
        self.assertFalse(res["fallback_used"])
        self.assertEqual(res["certificate_result_count"], 1)

    @patch("requests.get")
    def test_crtsh_empty_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        res = collect_domain_domains_detailed("example.com", max_retries=1)
        self.assertEqual(res["certificate_query_status"], "empty")
        self.assertTrue(res["certificate_source_available"])
        self.assertTrue(res["fallback_used"])
        self.assertEqual(res["certificate_result_count"], 0)

    @patch("requests.get")
    def test_crtsh_rate_limited(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        res = collect_domain_domains_detailed("example.com", max_retries=1)
        self.assertEqual(res["certificate_query_status"], "rate_limited")
        self.assertFalse(res["certificate_source_available"])
        self.assertTrue(res["fallback_used"])

    @patch("requests.get")
    def test_crtsh_server_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 504
        mock_get.return_value = mock_resp

        res = collect_domain_domains_detailed("example.com", max_retries=1)
        self.assertEqual(res["certificate_query_status"], "server_error")
        self.assertFalse(res["certificate_source_available"])
        self.assertTrue(res["fallback_used"])

    @patch("requests.get")
    def test_crtsh_json_parse_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Bad JSON")
        mock_get.return_value = mock_resp

        res = collect_domain_domains_detailed("example.com", max_retries=1)
        self.assertEqual(res["certificate_query_status"], "parse_error")
        self.assertFalse(res["certificate_source_available"])
        self.assertTrue(res["fallback_used"])


class TestDnsSecurityParsing(unittest.TestCase):
    def test_spf_strict(self):
        txt = ['"v=spf1 ip4:192.0.2.1 -all"']
        res = parse_spf(txt, "NOERROR")
        self.assertTrue(res["has_spf"])
        self.assertEqual(res["spf_status"], "valid")
        self.assertEqual(res["spf_policy"], "strict_hardfail")
        self.assertFalse(res["weak_spf"])

    def test_spf_weak_softfail(self):
        txt = ['"v=spf1 include:_spf.google.com ~all"']
        res = parse_spf(txt, "NOERROR")
        self.assertTrue(res["has_spf"])
        self.assertEqual(res["spf_policy"], "weak_softfail")
        self.assertTrue(res["weak_spf"])

    def test_spf_absent(self):
        txt = ['"google-site-verification=xyz"']
        res = parse_spf(txt, "NOERROR")
        self.assertFalse(res["has_spf"])
        self.assertEqual(res["spf_status"], "absent")

    def test_spf_malformed_multiple_records(self):
        txt = ['"v=spf1 mx -all"', '"v=spf1 include:mail.com ~all"']
        res = parse_spf(txt, "NOERROR")
        self.assertFalse(res["has_spf"])
        self.assertEqual(res["spf_status"], "malformed")
        self.assertEqual(res["spf_policy"], "multiple_records_prohibited")

    def test_spf_query_failed(self):
        res = parse_spf([], "TIMEOUT")
        self.assertFalse(res["has_spf"])
        self.assertEqual(res["spf_status"], "query_failed")

    def test_dmarc_reject(self):
        dmarc = ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"']
        res = parse_dmarc(dmarc, "NOERROR")
        self.assertTrue(res["has_dmarc"])
        self.assertEqual(res["dmarc_status"], "valid")
        self.assertEqual(res["dmarc_policy"], "reject")
        self.assertTrue(res["dmarc_enforced"])

    def test_dmarc_quarantine(self):
        dmarc = ['"v=DMARC1; p=quarantine; sp=reject;"']
        res = parse_dmarc(dmarc, "NOERROR")
        self.assertTrue(res["has_dmarc"])
        self.assertEqual(res["dmarc_policy"], "quarantine")
        self.assertTrue(res["dmarc_enforced"])

    def test_dmarc_none_monitoring(self):
        dmarc = ['"v=DMARC1; p=none;"']
        res = parse_dmarc(dmarc, "NOERROR")
        self.assertTrue(res["has_dmarc"])
        self.assertEqual(res["dmarc_policy"], "none")
        self.assertFalse(res["dmarc_enforced"])

    def test_dmarc_absent(self):
        res = parse_dmarc([], "NOERROR")
        self.assertFalse(res["has_dmarc"])
        self.assertEqual(res["dmarc_status"], "absent")

    def test_dmarc_malformed_multiple(self):
        dmarc = ['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"']
        res = parse_dmarc(dmarc, "NOERROR")
        self.assertFalse(res["has_dmarc"])
        self.assertEqual(res["dmarc_status"], "malformed")

    def test_dmarc_query_failed(self):
        res = parse_dmarc([], "TIMEOUT")
        self.assertFalse(res["has_dmarc"])
        self.assertEqual(res["dmarc_status"], "query_failed")


class TestResearchDatasetAndAnonymization(unittest.TestCase):
    def test_domain_hash_deterministic(self):
        h1 = domain_hash("EXAMPLE.COM", salt="test-salt")
        h2 = domain_hash("https://www.example.com/", salt="test-salt")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 16)

    def test_measure_provenance_separation(self):
        row = {"country": "nigeria", "sector": "universities", "organization_id": "NG-UNI-001", "domain": "unilag.edu.ng"}
        report = {
            "metrics": {
                "certificate_domains": 10,
                "dns_domains": 10,
                "resolved_subdomains": 5,
                "discovered_ips": 8,
                "spf_domains": 1,
                "dmarc_domains": 1,
            },
            "provenance": {
                "certificate_transparency": {
                    "certificate_query_status": "success",
                    "certificate_source_available": True,
                    "fallback_used": False,
                    "certificate_result_count": 10,
                }
            },
            "findings": [],
            "posture": {"score": 90}
        }
        dns_data = [{
            "domain": "unilag.edu.ng",
            "security": {
                "has_spf": True,
                "spf_status": "valid",
                "spf_policy": "strict_hardfail",
                "weak_spf": False,
                "has_dmarc": True,
                "dmarc_status": "valid",
                "dmarc_policy": "reject",
                "dmarc_enforced": True,
                "self_hosted_mail": True,
            }
        }]
        m = _measure(row, report, "test-salt", "2026-08-26", dns_data=dns_data)
        self.assertEqual(m["country"], "nigeria")
        self.assertEqual(m["sector"], "universities")
        self.assertEqual(m["dmarc_policy"], "reject")
        self.assertTrue(m["dmarc_enforced"])
        self.assertEqual(m["observed_asset_coverage"], 1.0)
        self.assertTrue(m["certificate_source_available"])

    def test_coverage_null_on_fallback(self):
        row = {"country": "ghana", "sector": "government", "organization_id": "GH-GOV-001", "domain": "ghana.gov.gh"}
        report = {
            "metrics": {"certificate_domains": 1, "dns_domains": 1, "resolved_subdomains": 2, "discovered_ips": 2},
            "provenance": {
                "certificate_transparency": {
                    "certificate_query_status": "timeout",
                    "certificate_source_available": False,
                    "fallback_used": True,
                    "certificate_result_count": 0,
                }
            },
            "findings": [],
            "posture": {"score": 60}
        }
        m = _measure(row, report, "test-salt", "2026-08-26", dns_data=[])
        self.assertIsNone(m["observed_asset_coverage"])
        self.assertFalse(m["certificate_source_available"])


class TestStatisticalEngine(unittest.TestCase):
    def test_wilson_score_interval(self):
        low, high = wilson_score_interval(26, 30)
        self.assertAlmostEqual(low, 0.703, places=2)
        self.assertAlmostEqual(high, 0.947, places=2)

    def test_chi_square_contingency(self):
        # 2x2 table: [[0, 6], [22, 2]]
        chi2, p_val = chi_square_2x2(0, 6, 22, 2)
        self.assertGreater(chi2, 10.0)
        self.assertLess(p_val, 0.001)

    def test_kruskal_wallis(self):
        g1 = [1, 2, 3]
        g2 = [4, 5, 6]
        g3 = [7, 8, 9]
        h, p_val = kruskal_wallis(g1, g2, g3)
        self.assertGreater(h, 5.0)
        self.assertLess(p_val, 0.05)


if __name__ == "__main__":
    unittest.main()
