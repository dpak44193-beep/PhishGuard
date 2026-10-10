"""Tests for URLFeatureExtractor — all 30 features, edge cases, and vector shape."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.features.extractor import URLFeatureExtractor, FEATURE_ORDER


@pytest.fixture
def extractor():
    return URLFeatureExtractor()


class TestVectorShape:
    def test_returns_30_features(self, extractor):
        vec = extractor.to_vector(extractor.extract("https://example.com"))
        assert vec.shape == (30,)

    def test_feature_order_has_30_entries(self):
        assert len(FEATURE_ORDER) == 30

    def test_feature_keys_match_order(self, extractor):
        feats = extractor.extract("https://example.com/path")
        assert set(feats.keys()) == set(FEATURE_ORDER)

    def test_vector_dtype_is_float(self, extractor):
        vec = extractor.to_vector(extractor.extract("https://example.com"))
        assert vec.dtype == float


class TestUrlLengthAndDomain:
    def test_url_length_correct(self, extractor):
        url = "http://abc.com/path"
        feats = extractor.extract(url)
        assert feats["url_length"] == len(url)

    def test_domain_length_strips_www(self, extractor):
        feats = extractor.extract("https://www.google.com/")
        assert feats["domain_length"] == len("google.com")

    def test_subdomain_count_none(self, extractor):
        feats = extractor.extract("https://google.com/")
        assert feats["subdomain_count"] == 0

    def test_subdomain_count_one(self, extractor):
        feats = extractor.extract("https://mail.google.com/")
        assert feats["subdomain_count"] == 1

    def test_subdomain_count_two(self, extractor):
        feats = extractor.extract("https://a.b.google.com/")
        assert feats["subdomain_count"] == 2


class TestProtocolAndIPFlags:
    def test_https_flag_true(self, extractor):
        assert extractor.extract("https://example.com")["uses_https"] is True

    def test_https_flag_false(self, extractor):
        assert extractor.extract("http://example.com")["uses_https"] is False

    def test_has_ip_true(self, extractor):
        assert extractor.extract("http://192.168.1.1/path")["has_ip"] is True

    def test_has_ip_false(self, extractor):
        assert extractor.extract("https://google.com")["has_ip"] is False

    def test_has_port_true(self, extractor):
        assert extractor.extract("http://example.com:8080/path")["has_port"] is True

    def test_has_port_false(self, extractor):
        assert extractor.extract("https://example.com/path")["has_port"] is False


class TestSuspiciousSignals:
    def test_suspicious_keywords_counted(self, extractor):
        feats = extractor.extract("http://paypal-login-verify.com/secure")
        assert feats["suspicious_keywords"] >= 2  # login, verify

    def test_suspicious_keywords_zero_for_clean(self, extractor):
        feats = extractor.extract("https://github.com/user/repo")
        assert feats["suspicious_keywords"] == 0

    def test_tld_risk_high_for_xyz(self, extractor):
        assert extractor.extract("http://bad-site.xyz/")["tld_risk"] == 1.0

    def test_tld_risk_zero_for_com(self, extractor):
        assert extractor.extract("https://example.com/")["tld_risk"] == 0.0

    def test_url_shortener_flag(self, extractor):
        feats = extractor.extract("https://bit.ly/abc123")
        assert feats["is_url_shortener"] is True
        assert feats["url_shortener_flag"] == 1

    def test_at_sign_count(self, extractor):
        feats = extractor.extract("http://user@evil.com/page")
        assert feats["at_sign_count"] == 1

    def test_encoded_chars_detected(self, extractor):
        feats = extractor.extract("http://example.com/path%20with%20spaces")
        assert feats["has_encoded_chars"] is True

    def test_punycode_detected(self, extractor):
        feats = extractor.extract("http://xn--pple-43d.com/")
        assert feats["is_punycode"] is True

    def test_brand_in_domain(self, extractor):
        feats = extractor.extract("http://paypal-login.xyz/")
        assert feats["brand_count"] >= 1

    def test_multi_subdomain_true(self, extractor):
        feats = extractor.extract("http://a.b.c.evil.com/")
        assert feats["multi_subdomain"] == 1

    def test_multi_subdomain_false(self, extractor):
        feats = extractor.extract("http://evil.com/")
        assert feats["multi_subdomain"] == 0


class TestEntropyAndDigits:
    def test_entropy_positive(self, extractor):
        feats = extractor.extract("http://xkcd29abc.xyz/randompath")
        assert feats["entropy"] > 0.0

    def test_entropy_increases_with_randomness(self, extractor):
        clean = extractor.extract("https://google.com")
        random = extractor.extract("http://a1b2c3d4e5f6g7h8.xyz/q?x=y")
        assert random["entropy"] >= clean["entropy"]

    def test_digit_ratio_zero_for_letters_only(self, extractor):
        feats = extractor.extract("https://google.com/search")
        assert feats["digit_ratio"] == 0.0

    def test_fragment_detected(self, extractor):
        feats = extractor.extract("https://example.com/page#section")
        assert feats["fragment_present"] is True

    def test_query_length(self, extractor):
        feats = extractor.extract("https://example.com/?q=hello&x=1")
        assert feats["query_length"] == len("q=hello&x=1")
        assert feats["query_param_count"] == 2
