import json
from io import StringIO
import unittest
from unittest.mock import patch

from amf.cli import main
from amf.console import AMFConsole
from amf.core import get_module, list_modules
from amf.modules.http_headers import HTTPHeadersModule
from amf.safety import SafetyError, SafetyPolicy, load_allowlist


class FrameworkTests(unittest.TestCase):
    def test_builtin_module_is_registered(self):
        names = [module.name for module in list_modules()]
        self.assertIn("scanner/http_headers", names)
        self.assertEqual(get_module("scanner/http_headers").name, "scanner/http_headers")

    def test_allowlist_rejects_unknown_target(self):
        policy = SafetyPolicy(load_allowlist(["https://lab.local"]))
        with self.assertRaises(SafetyError):
            policy.validate("https://other.local")

    def test_dry_run_does_not_open_network(self):
        with patch("urllib.request.urlopen") as opener:
            self.assertEqual(main(["check", "scanner/http_headers", "https://lab.local", "--allow", "https://lab.local"]), 0)
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
