"""Tests for obfuscation detection and typosquatting checks."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.features.obfuscation import detect_obfuscation_signals, decode_url
from ml.features.typosquatting import check_typosquatting, levenshtein


class TestObfuscation:
    def test_clean_url_no_signals(self):
        assert detect_obfuscation_signals("https://google.com/search?q=hello") == []

    def test_percent_encoding_detected(self):
        sigs = detect_obfuscation_signals("http://evil.com/path%20with%20space")
        assert "percent_encoding" in sigs

    def test_hex_ip_detected(self):
        sigs = detect_obfuscation_signals("http://0xc0a80001/page")
        assert "hex_ip" in sigs

    def test_punycode_detected(self):
        sigs = detect_obfuscation_signals("http://xn--pple-43d.com/")
        assert "punycode_idn" in sigs

    def test_double_slash_redirect_detected(self):
        sigs = detect_obfuscation_signals("http://evil.com//redirect//target")
        assert "double_slash_redirect" in sigs

    def test_at_sign_misdirect_detected(self):
        sigs = detect_obfuscation_signals("http://legit.com@evil.com/")
        assert "at_sign_misdirect" in sigs

    def test_multiple_signals_combined(self):
        url = "http://user@0x7f000001/path%20encoded"
        sigs = detect_obfuscation_signals(url)
        assert "at_sign_misdirect" in sigs
        assert "percent_encoding" in sigs
        assert "hex_ip" in sigs


class TestDecodeUrl:
    def test_percent_encoding_decoded(self):
        result = decode_url("http://evil.com/path%20file")
        assert "%20" not in result
        assert "path file" in result

    def test_hex_ip_decoded(self):
        result = decode_url("http://0xc0000001/")
        assert "0xc0000001" not in result

    def test_clean_url_unchanged(self):
        url = "https://google.com/search"
        assert decode_url(url) == url


class TestLevenshtein:
    def test_identical_strings_zero(self):
        assert levenshtein("paypal", "paypal") == 0

    def test_single_substitution(self):
        assert levenshtein("paypa1", "paypal") == 1

    def test_empty_string(self):
        assert levenshtein("", "abc") == 3
        assert levenshtein("abc", "") == 3

    def test_symmetric(self):
        assert levenshtein("kitten", "sitting") == levenshtein("sitting", "kitten")


class TestTyposquatting:
    def test_exact_brand_not_flagged(self):
        result = check_typosquatting("paypal.com")
        assert result["is_typosquatting"] is False

    def test_single_char_swap_flagged(self):
        result = check_typosquatting("paypa1.com")
        assert result["is_typosquatting"] is True
        assert result["closest_brand"] == "paypal.com"
        assert result["edit_distance"] == 1

    def test_clean_domain_not_flagged(self):
        result = check_typosquatting("openai.com")
        assert result["is_typosquatting"] is False

    def test_returns_closest_brand(self):
        result = check_typosquatting("g00gle.com")
        assert "google.com" in result["closest_brand"]

    def test_result_has_required_keys(self):
        result = check_typosquatting("example.com")
        assert {"closest_brand", "edit_distance", "is_typosquatting"} == set(result.keys())
