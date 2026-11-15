"""Il report segnala le credenziali esposte senza riprodurle.

Un report viene allegato a un ticket, inoltrato, lasciato aperto su uno schermo:
deve dire *che cosa* è esposto e *dove*, mai il valore. Questi test verificano
la funzione di mascheramento e, soprattutto, l'uscita reale dello strumento
(console e HTML) su un HAR costruito apposta.
"""

import os
import subprocess
import sys
import tempfile
import unittest

from .test_harootcase import SCRIPT_PATH, hc, make_entry, make_har, write_har

PASSWORD = "PasswordInChiaro99"
API_KEY = "CHIAVE-SUPER-SEGRETA-12345"
FORM_TOKEN = "tok_live_9f8e7d6c5b4a3210"
JSON_SECRET = "s3greto-nel-json-ABCDEF"
BEARER = "abcDEF123456ghiJKL7890mnoPQR"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSJ9."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
BASIC_USER_PASS = "ada:Segreta123"
CARD = "4111111111111111"            # numero di prova, supera il controllo di Luhn
EMAIL_LOCAL = "mario.rossi.privato"

ALL_SECRETS = [PASSWORD, API_KEY, FORM_TOKEN, JSON_SECRET, BEARER, JWT, BASIC_USER_PASS, CARD]


class TestMaskSecrets(unittest.TestCase):
    def test_sensitive_query_parameters(self):
        cases = {
            "https://x.test/login?user=ada&password=" + PASSWORD: "https://x.test/login?user=ada&password=[REDACTED]",
            "https://x.test/v1?api_key=" + API_KEY + "&page=2": "https://x.test/v1?api_key=[REDACTED]&page=2",
            "a=1&access_token=abc.def&b=2": "a=1&access_token=[REDACTED]&b=2",
            "?code=4/0AX4XfWh&state=xyz": "?code=[REDACTED]&state=xyz",
            "client_secret=zzz": "client_secret=[REDACTED]",
            "PASSWORD=Maiuscolo": "PASSWORD=[REDACTED]",
            "sessionid=abc123; path=/": "sessionid=[REDACTED]; path=/",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(hc.mask_secrets(text), expected)

    def test_the_parameter_name_is_kept_and_harmless_ones_are_untouched(self):
        text = "https://x.test/search?q=password+reset&page=2&monkey=1&keyboard=it&lang=it"
        self.assertEqual(hc.mask_secrets(text), text)

    def test_json_bodies(self):
        self.assertEqual(hc.mask_secrets('{"user": "ada", "password": "' + JSON_SECRET + '"}'),
                         '{"user": "ada", "password": "[REDACTED]"}')
        self.assertEqual(hc.mask_secrets("{'token':'abc', 'n': 1}"), "{'token':'[REDACTED]', 'n': 1}")
        self.assertEqual(hc.mask_secrets('{"password": "con \\"virgolette\\" dentro"}'),
                         '{"password": "[REDACTED]"}')

    def test_tokens_in_free_text(self):
        self.assertEqual(hc.mask_secrets("Authorization: Bearer " + BEARER), "Authorization: Bearer [REDACTED]")
        self.assertEqual(hc.mask_secrets("jwt nel corpo: " + JWT + " fine"), "jwt nel corpo: [REDACTED] fine")
        self.assertEqual(hc.mask_secrets("https://" + BASIC_USER_PASS + "@x.test/a"), "https://[REDACTED]@x.test/a")

    def test_prose_is_not_mangled(self):
        for text in ("Usa la basic authentication solo su HTTPS.",
                     "Il bearer token va nell'header.",
                     "Tempo totale 1234567890123 ms, id 20261115093000123",
                     "HTTP 500: GET https://x.test/api/items/42",
                     "", "nessun segreto qui"):
            with self.subTest(text=text):
                self.assertEqual(hc.mask_secrets(text), text)

    def test_card_numbers_keep_only_the_last_four_digits(self):
        self.assertEqual(hc.mask_secrets("card=" + CARD + "&x=1"), "card=[carta •••• 1111]&x=1")
        self.assertEqual(hc.mask_secrets("4111 1111 1111 1111"), "[carta •••• 1111]")
        self.assertEqual(hc.mask_secrets("4111-1111-1111-1111"), "[carta •••• 1111]")

    def test_emails_keep_the_first_letter_and_the_domain(self):
        self.assertEqual(hc.mask_secrets("scrivi a mario.rossi@example.com oggi"),
                         "scrivi a m•••@example.com oggi")
        self.assertEqual(hc.mask_secrets("?email=ada%2Btest@mail.example.org&x=1"),
                         "?email=a•••@mail.example.org&x=1")

    def test_file_names_that_look_like_emails_are_left_alone(self):
        for text in ("https://cdn.test/img/logo@2x.png", "/static/icon@3x.webp", "bundle@1.2.js"):
            with self.subTest(text=text):
                self.assertEqual(hc.mask_secrets(text), text)

    def test_numbers_that_are_not_cards_are_left_alone(self):
        for text in ("4111111111111112",          # stessa lunghezza, Luhn sbagliato
                     "0000000000000000", "1699999999999", "id=1234567890123456789012"):
            with self.subTest(text=text):
                self.assertEqual(hc.mask_secrets(text), text)

    def test_idempotent(self):
        for text in ("?password=" + PASSWORD, "Bearer " + BEARER, JWT, '{"token": "x"}', "card " + CARD,
                     "mario.rossi@example.com"):
            once = hc.mask_secrets(text)
            self.assertEqual(hc.mask_secrets(once), once)

    def test_none_and_non_strings(self):
        self.assertEqual(hc.mask_secrets(None), "")
        self.assertEqual(hc.mask_secrets(42), "42")


class TestShownValues(unittest.TestCase):
    def test_short_url_masks_before_truncating(self):
        """Tagliando prima, un valore troncato a metà non verrebbe più riconosciuto."""
        url = "https://x.test/a/very/long/path/that/goes/on?password=" + PASSWORD + "&other=1"
        for maxlen in (30, 50, 60, 70, 90, 200):
            with self.subTest(maxlen=maxlen):
                shown = hc.short_url(url, maxlen)
                self.assertLessEqual(len(shown), maxlen)
                self.assertNotIn("PasswordIn", shown)
                self.assertNotIn(PASSWORD[:6], shown)

    def test_short_url_without_secrets_is_unchanged(self):
        self.assertEqual(hc.short_url("https://x.test/a?page=2"), "https://x.test/a?page=2")
        self.assertEqual(hc.short_url("x" * 100, 20), "x" * 17 + "...")

    def test_describe_pii_never_contains_the_value(self):
        samples = {
            "api_key_in_url": "password=" + PASSWORD,
            "bearer_token": "Bearer " + BEARER,
            "jwt": JWT,
            "credit_card": CARD,
            "email": EMAIL_LOCAL + "@example.com",
            "qualcosa_di_nuovo": "valore-ignoto-123",
        }
        secrets = [PASSWORD, BEARER, JWT, CARD, EMAIL_LOCAL, "valore-ignoto-123"]
        for pii_type, matched in samples.items():
            with self.subTest(pii_type=pii_type):
                shown = hc.describe_pii(pii_type, matched)
                for secret in secrets:
                    self.assertNotIn(secret, shown)
        self.assertEqual(hc.describe_pii("api_key_in_url", "password=" + PASSWORD), "password=[REDACTED] (18 caratteri)")
        self.assertEqual(hc.describe_pii("credit_card", CARD), "[carta •••• 1111]")
        self.assertEqual(hc.describe_pii("email", "mario@example.com"), "m•••@example.com")

    def test_url_without_query(self):
        self.assertEqual(hc.url_without_query("https://x.test/login?password=" + PASSWORD + "#frag"),
                         "https://x.test/login?…")
        self.assertEqual(hc.url_without_query("https://x.test/login"), "https://x.test/login")

    def test_findings_are_masked_at_the_source(self):
        finding = hc.Finding(
            severity=hc.Severity.HIGH, category=hc.FindingCategory.SECURITY, finding_type="X",
            title="token=" + FORM_TOKEN, detail="GET https://x.test/?password=" + PASSWORD,
            insight="Bearer " + BEARER,
            evidence={"url": "https://x.test/?api_key=" + API_KEY, "list": ["jwt " + JWT], "n": 3,
                      "nested": {"body": '{"secret": "' + JSON_SECRET + '"}'}})
        blob = repr(finding)
        for secret in (FORM_TOKEN, PASSWORD, BEARER, API_KEY, JWT, JSON_SECRET):
            self.assertNotIn(secret, blob)
        self.assertEqual(finding.evidence["n"], 3)
        self.assertIn("password=[REDACTED]", finding.detail)

    def test_kb_matches_are_masked_at_the_source(self):
        match = hc.KBMatch(pattern_id="p", pattern_name="n", severity="HIGH", confidence="alta",
                           evidence={"url": "https://x.test/?password=" + PASSWORD},
                           diagnosis="visto access_token=" + FORM_TOKEN, solutions=[])
        self.assertNotIn(PASSWORD, repr(match))
        self.assertNotIn(FORM_TOKEN, repr(match))


def hostile_har():
    """Un HAR con una credenziale in ogni posto in cui può finire."""
    entries = [
        make_entry("https://shop.test/"),
        make_entry("https://shop.test/login", request_query_text=f"user=ada&password={PASSWORD}"),
        make_entry("https://api.shop.test/v1/items", status=500, time_total=4200.0, wait=4000.0,
                   request_query_text=f"api_key={API_KEY}&page=2", mime="application/json",
                   response_text='{"error": "boom", "secret": "' + JSON_SECRET + '"}'),
        make_entry("https://api.shop.test/v1/session", method="POST", status=401,
                   post_data_text=f"grant=x&token={FORM_TOKEN}", mime="application/json",
                   request_headers=[{"name": "Authorization", "value": "Bearer " + BEARER}],
                   response_text='{"id_token": "' + JWT + '"}'),
        make_entry(f"https://{BASIC_USER_PASS}@legacy.shop.test/export", status=404),
        make_entry("https://shop.test/pay", status=502, time_total=3100.0, wait=3000.0,
                   request_query_text=f"card={CARD}&email={EMAIL_LOCAL}@example.com"),
        make_entry("https://cdn.shop.test/app.js", mime="application/javascript", transfer_size=900000),
    ]
    return make_har(entries, page_url="https://shop.test/")


class TestReportEndToEnd(unittest.TestCase):
    """L'uscita vera dello strumento, come la vedrebbe chi lo usa."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        har = write_har(cls.tmp.name, "hostile.har", hostile_har())
        cls.html_path = os.path.join(cls.tmp.name, "report.html")
        cls.result = subprocess.run(
            [sys.executable, SCRIPT_PATH, har, "--no-open", "--html", cls.html_path],
            cwd=cls.tmp.name, capture_output=True, text=True, timeout=120)
        cls.console = cls.result.stdout + cls.result.stderr
        with open(cls.html_path, encoding="utf-8") as handle:
            cls.html = handle.read()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_run_succeeds_and_writes_the_report(self):
        self.assertEqual(self.result.returncode, 0, self.console[-1500:])
        self.assertGreater(len(self.html), 5000)

    def test_no_secret_value_in_the_console_output(self):
        for secret in ALL_SECRETS:
            with self.subTest(secret=secret[:10]):
                self.assertNotIn(secret, self.console)

    def test_no_secret_value_in_the_html_report(self):
        for secret in ALL_SECRETS:
            with self.subTest(secret=secret[:10]):
                self.assertNotIn(secret, self.html)

    def test_not_even_a_recognisable_prefix(self):
        """Prima il report mostrava i primi 30 caratteri del valore trovato."""
        for secret in (PASSWORD, API_KEY, FORM_TOKEN, JSON_SECRET):
            with self.subTest(secret=secret[:10]):
                self.assertNotIn(secret[:8], self.html)
                self.assertNotIn(secret[:8], self.console)

    def test_the_exposure_is_still_reported(self):
        """Mascherare non vuol dire tacere: il problema resta segnalato, con il nome del parametro."""
        self.assertIn("PII_API_KEY_IN_URL", self.html)
        self.assertIn("password=[REDACTED]", self.html)
        self.assertIn("api_key=[REDACTED]", self.html)
        self.assertIn("[REDACTED]", self.console)

    def test_the_card_is_reported_by_its_last_digits_only(self):
        self.assertIn("PII_CREDIT_CARD", self.html)
        self.assertIn("•••• 1111", self.html)

    def test_the_email_is_masked_everywhere(self):
        """Segnalata come PII in un punto, non deve ricomparire intera nella URL di un altro."""
        self.assertIn("PII_EMAIL", self.html)
        self.assertIn("m•••@example.com", self.html)
        self.assertNotIn(EMAIL_LOCAL, self.html)
        self.assertNotIn(EMAIL_LOCAL, self.console)

    def test_urls_stay_readable(self):
        """Host e percorso servono alla diagnosi e restano."""
        for fragment in ("api.shop.test/v1/items", "shop.test/login", "legacy.shop.test/export"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.html)


class TestRepositoryHygiene(unittest.TestCase):
    def test_help_names_the_real_script(self):
        out = subprocess.run([sys.executable, SCRIPT_PATH, "--help"], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0)
        self.assertIn("HARootCase.py", out.stdout)
        self.assertNotIn("har_analyzer_pro", out.stdout)


if __name__ == "__main__":
    unittest.main()
