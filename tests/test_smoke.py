import unittest

from amf.cli import main


class SmokeTests(unittest.TestCase):
    def test_cli_list_runs(self):
        result = main(["list"])
        self.assertEqual(result, 0)

    def test_cli_profiles_runs(self):
        result = main(["profiles"])
        self.assertEqual(result, 0)

    def test_cli_doctor_runs(self):
        result = main(["doctor"])
        self.assertEqual(result, 0)

    def test_cli_info_runs(self):
        result = main(["info", "scanner/http_headers"])
        self.assertEqual(result, 0)

    def test_cli_dry_run_runs(self):
        result = main([
            "check",
            "scanner/http_headers",
            "https://lab.local",
            "--allow",
            "https://lab.local"
        ])
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
