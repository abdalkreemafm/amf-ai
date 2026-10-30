import json
from io import StringIO
import unittest
from unittest.mock import patch

from amf.cli import main
from amf.console import AMFConsole
from amf.core import get_module, list_modules, search_modules
from amf.profiles import profile_modules
from amf.modules.http_cookies import HTTPCookiesModule
from amf.modules.dns_basic import DNSBasicModule
from amf.modules.tls_certificate import TLSCertificateModule
from amf.modules.http_utils import HTTPDocument
from amf.modules.http_sql_errors import SQLDatabaseErrorModule
from amf.modules.http_xss_surface import XSSSurfaceModule
from amf.modules.server_misconfiguration import ServerMisconfigurationModule
from amf.reporting import to_json
from amf.reporting import to_sarif
from amf.modules.http_headers import HTTPHeadersModule
from amf.safety import SafetyError, SafetyPolicy, load_allowlist
from amf.api import run_scan
from amf.integrations import ADAPTERS, tool_catalog


class FrameworkTests(unittest.TestCase):
    def test_builtin_module_is_registered(self):
        names = [module.name for module in list_modules()]
        self.assertIn("scanner/http_headers", names)
        self.assertIn("scanner/http_cookies", names)
        self.assertIn("scanner/http_redirects", names)
        self.assertIn("scanner/tls_certificate", names)
        self.assertIn("scanner/dns_basic", names)
        self.assertIn("scanner/http_sql_errors", names)
        self.assertIn("scanner/http_xss_surface", names)
        self.assertIn("scanner/server_misconfiguration", names)
        self.assertIn("scanner/http_cors", names)
        self.assertIn("scanner/sensitive_files", names)
        self.assertIn("scanner/dns_email_security", names)
        self.assertEqual(get_module("scanner/http_headers").name, "scanner/http_headers")

    def test_module_metadata_and_search_catalog(self):
        module = get_module("scanner/http_headers")
        self.assertEqual(module.metadata()["category"], "scanner")
        self.assertIn(module.name, [item.name for item in search_modules("headers")])
        self.assertTrue(profile_modules("web"))

    def test_sarif_report_is_valid(self):
        from amf.core import Finding, RunResult
        payload = json.loads(to_sarif([RunResult("test", "https://lab.local", "execute", "now", [Finding("test", "High", "high", "desc", "fix")])]))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"][0]["results"]), 1)

    def test_sensitive_file_evidence_is_redacted(self):
        from amf.modules.sensitive_files import SensitiveFilesModule
        document = HTTPDocument(200, {}, "API_KEY=super-secret-value")
        with patch("amf.modules.sensitive_files.fetch_document", return_value=document):
            findings = SensitiveFilesModule().run("https://lab.local")
        self.assertTrue(findings)
        self.assertNotIn("super-secret-value", json.dumps(findings[0].evidence))
        self.assertIn("REDACTED", findings[0].evidence["content_preview"])

    def test_local_api_scan_defaults_to_dry_run(self):
        results = run_scan({"target": "https://lab.local", "allow": ["https://lab.local"], "profile": "quick"})
        self.assertEqual(len(results), 4)
        self.assertTrue(all(result.mode == "dry-run" for result in results))

    def test_local_api_rejects_target_outside_allowlist(self):
        with self.assertRaises(SafetyError):
            run_scan({"target": "https://other.local", "allow": ["https://lab.local"]})

    def test_external_tool_catalog_reports_expected_adapters(self):
        names = {item["name"] for item in tool_catalog()}
        self.assertEqual(names, {"dns", "openssl", "nmap"})

    def test_external_command_is_dry_run_without_execute(self):
        with patch.object(ADAPTERS["dns"], "run") as adapter_run:
            self.assertEqual(main(["external", "dns", "https://lab.local", "--allow", "https://lab.local"]), 0)
            adapter_run.assert_not_called()

    def test_finding_report_contains_type_severity_and_languages(self):
        from amf.core import Finding, RunResult

        result = RunResult("test", "https://lab.local", "execute", "now", [Finding("test", "Missing header", "HIGH", "missing", "fix", finding_type="http-header", title_ar="رأس مفقود", title_en="Missing header")])
        payload = json.loads(to_json([result], "both"))
        finding = payload[0]["findings"][0]
        self.assertEqual(finding["type"], "http-header")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["title_ar"], "رأس مفقود")
        self.assertEqual(finding["title_en"], "Missing header")

    def test_allowlist_rejects_unknown_target(self):
        policy = SafetyPolicy(load_allowlist(["https://lab.local"]))
        with self.assertRaises(SafetyError):
            policy.validate("https://other.local")

    def test_dry_run_does_not_open_network(self):
        with patch("urllib.request.urlopen") as opener:
            self.assertEqual(main(["check", "scanner/http_headers", "https://lab.local", "--allow", "https://lab.local"]), 0)
            opener.assert_not_called()

    def test_full_dry_run_does_not_open_network(self):
        with patch("urllib.request.urlopen") as opener:
            self.assertEqual(main(["full", "https://lab.local", "--allow", "https://lab.local"]), 0)
            opener.assert_not_called()

    def test_report_is_valid_json(self):
        with patch("builtins.print") as printer:
            self.assertEqual(main(["check", "scanner/http_headers", "https://lab.local", "--allow", "https://lab.local"]), 0)
        payload = printer.call_args_list[-1].args[0]
        data = json.loads(payload)
        self.assertEqual(data[0]["mode"], "dry-run")

    def test_allowlist_rejects_non_http_urls(self):
        with self.assertRaises(SafetyError):
            load_allowlist(["file:///tmp/test"])

    def test_http_module_reports_missing_headers(self):
        class Response:
            status = 200
            headers = {"Server": "test-server"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with patch("amf.modules.http_headers.urlopen", return_value=Response()):
            findings = HTTPHeadersModule().run("https://lab.local")
        titles = {finding.title for finding in findings}
        self.assertIn("Missing HSTS header", titles)
        self.assertIn("Server header exposed", titles)

    def test_cookie_module_reports_cookie_attributes(self):
        class Response:
            headers = {"Set-Cookie": "session=abc"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with patch("amf.modules.http_cookies.urlopen", return_value=Response()):
            findings = HTTPCookiesModule().run("https://lab.local")
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(item.finding_type == "cookie-security" for item in findings))

    def test_tls_module_rejects_non_https_without_network(self):
        findings = TLSCertificateModule().run("http://lab.local")
        self.assertEqual(findings[0].finding_type, "input-validation")
        self.assertEqual(findings[0].severity, "info")

    def test_dns_module_reports_resolved_addresses(self):
        with patch("amf.modules.dns_basic.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 80)), (10, 1, 6, "", ("::1", 80))]):
            findings = DNSBasicModule().run("http://lab.local")
        self.assertEqual(findings[0].finding_type, "asset-discovery")
        self.assertIn("127.0.0.1", findings[0].evidence["addresses"])

    def test_sql_module_only_reports_passive_error_disclosure(self):
        document = HTTPDocument(500, {"Content-Type": "text/html"}, "Database error: PostgreSQL pg_query failed")
        with patch("amf.modules.http_sql_errors.fetch_document", return_value=document):
            findings = SQLDatabaseErrorModule().run("https://lab.local")
        self.assertEqual(findings[0].finding_type, "sql-error-disclosure")
        self.assertEqual(findings[0].severity, "medium")

    def test_xss_module_reports_review_signal_without_payload(self):
        document = HTTPDocument(200, {}, '<form><input></form><script>element.innerHTML = value</script>')
        with patch("amf.modules.http_xss_surface.fetch_document", return_value=document):
            findings = XSSSurfaceModule().run("https://lab.local")
        self.assertEqual(findings[0].finding_type, "xss-risk-indicator")
        self.assertEqual(findings[0].confidence, "low")

    def test_server_module_reports_disclosure_and_directory_listing(self):
        document = HTTPDocument(200, {"Server": "Example/1.0"}, "<title>Index of /backup</title>")
        with patch("amf.modules.server_misconfiguration.fetch_document", return_value=document):
            findings = ServerMisconfigurationModule().run("https://lab.local")
        types = {finding.finding_type for finding in findings}
        self.assertEqual(types, {"information-disclosure", "directory-listing"})

    def test_console_check_is_dry_run(self):
        output = StringIO()
        console = AMFConsole(output=output)
        console.onecmd("use scanner/http_headers")
        console.onecmd("set TARGET https://lab.local")
        console.onecmd("set ALLOW https://lab.local")
        with patch("urllib.request.urlopen") as opener:
            console.onecmd("check")
            opener.assert_not_called()
        self.assertIn("dry-run", output.getvalue())

    def test_console_run_requires_explicit_execute(self):
        output = StringIO()
        console = AMFConsole(output=output)
        console.onecmd("use scanner/http_headers")
        console.onecmd("set TARGET https://lab.local")
        console.onecmd("set ALLOW https://lab.local")
        console.onecmd("run")
        self.assertIn("run blocked", output.getvalue())


if __name__ == "__main__":
    unittest.main()
