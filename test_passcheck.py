import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

import passcheck


class AnalyzeTests(unittest.TestCase):
    def test_empty_password(self):
        result = passcheck.analyze("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["verdict"], "very weak")

    def test_common_password_scores_zero(self):
        for common in ("password", "123456", "qwerty", "P@ssw0rd".lower()):
            result = passcheck.analyze(common)
            self.assertEqual(result["score"], 0, common)
            self.assertTrue(any("commonly used" in f for f in result["findings"]))

    def test_common_password_case_insensitive(self):
        result = passcheck.analyze("PASSWORD")
        self.assertEqual(result["score"], 0)

    def test_short_password_gets_length_suggestion(self):
        result = passcheck.analyze("aB1$x")
        self.assertTrue(any("12 characters" in s for s in result["suggestions"]))

    def test_sequence_penalized(self):
        result = passcheck.analyze("Zx9abcdQw!")
        self.assertTrue(any("sequence" in f for f in result["findings"]))

    def test_keyboard_sequence_penalized(self):
        result = passcheck.analyze("Qwerty9!xY")
        self.assertTrue(any("sequence" in f for f in result["findings"]))

    def test_reversed_sequence_penalized(self):
        result = passcheck.analyze("Zx9dcbaQw!")
        self.assertTrue(any("sequence" in f for f in result["findings"]))

    def test_repeats_penalized(self):
        result = passcheck.analyze("Zx9aaaQw!1")
        self.assertTrue(any("repeated" in f for f in result["findings"]))

    def test_year_flagged(self):
        result = passcheck.analyze("Summer2017!x")
        self.assertTrue(any("date or year" in f for f in result["findings"]))

    def test_strong_passphrase_scores_high(self):
        result = passcheck.analyze("crimson-velvet-orchard-92-lantern!")
        self.assertGreaterEqual(result["score"], 3)

    def test_score_bounds(self):
        for candidate in ("a", "aB1!", "aB1!cD2@eF3#", "xK9#mQ2$vL8&pR4!zT7"):
            score = passcheck.analyze(candidate)["score"]
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 4)

    def test_entropy_monotonic_with_length(self):
        short = passcheck.entropy_bits("aB1!")
        long_ = passcheck.entropy_bits("aB1!aB1!aB1!")
        self.assertLess(short, long_)

    def test_entropy_empty(self):
        self.assertEqual(passcheck.entropy_bits(""), 0.0)

    def test_charset_size_counts_classes(self):
        self.assertEqual(passcheck.charset_size("abc"), 26)
        self.assertEqual(passcheck.charset_size("abcABC"), 52)
        self.assertEqual(passcheck.charset_size("abcABC123"), 62)
        self.assertEqual(passcheck.charset_size("abcABC123!"), 94)

    def test_only_digits_looks_like_date(self):
        result = passcheck.analyze("19900512")
        self.assertTrue(any("date or year" in f for f in result["findings"]))


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = passcheck.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_arg_password_warns_on_stderr(self):
        code, out, err = self.run_cli(["hunter2"])
        self.assertEqual(code, 0)
        self.assertIn("shell history", err)
        self.assertIn("Verdict:", out)

    def test_json_output_is_valid(self):
        code, out, _ = self.run_cli(["--json", "crimson-velvet-orchard-92-lantern!"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("score", data)
        self.assertIn("verdict", data)
        self.assertIn("entropy_bits", data)

    def test_missing_wordlist_fails(self):
        code, _, err = self.run_cli(["--wordlist", "/nonexistent/file.txt", "x"])
        self.assertEqual(code, 2)
        self.assertIn("could not read wordlist", err)

    def test_wordlist_adds_banned_passwords(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("mysecretword\n")
            path = fh.name
        try:
            code, out, _ = self.run_cli(["--json", "--wordlist", path, "mysecretword"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["score"], 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
