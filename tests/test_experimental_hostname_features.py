"""Tests for the isolated hostname-feature experiment."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.experiments.grouped_feature_experiment import (  # noqa: E402
    HOST_HASH_FEATURES,
    HOST_HASH_SCHEMA_VERSION,
    build_host_feature_matrix,
    host_character_hash_features,
)
from ml.features.extractor import FEATURE_ORDER, FEATURE_SCHEMA_VERSION  # noqa: E402


def test_experiment_keeps_the_production_30_feature_contract_unchanged():
    assert len(FEATURE_ORDER) == 30
    assert FEATURE_SCHEMA_VERSION == "phishguard-url-lexical-30-v1"
    assert HOST_HASH_SCHEMA_VERSION != FEATURE_SCHEMA_VERSION


def test_hostname_features_ignore_path_query_and_fragment_values():
    first = host_character_hash_features(
        ["https://accounts.example.org/login?token=private#step"]
    )
    second = host_character_hash_features(
        ["http://accounts.example.org/other?session=secret#different"]
    )

    np.testing.assert_array_equal(first, second)


def test_host_feature_matrix_has_a_separate_94_column_schema():
    base = np.zeros((2, len(FEATURE_ORDER)), dtype=float)
    urls = ["https://example.org/", "https://different.test/"]

    matrix = build_host_feature_matrix(base, urls)

    assert matrix.shape == (2, len(FEATURE_ORDER) + HOST_HASH_FEATURES)
    assert np.isfinite(matrix).all()
    assert not np.array_equal(matrix[0, len(FEATURE_ORDER):], matrix[1, len(FEATURE_ORDER):])


def test_host_feature_matrix_rejects_incompatible_base_contract():
    with np.testing.assert_raises(ValueError):
        build_host_feature_matrix(np.zeros((1, 29)), ["https://example.org/"])
