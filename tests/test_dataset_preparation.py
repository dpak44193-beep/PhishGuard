import csv
import json

from ml.data.download_dataset import prepare_dataset
import numpy as np
from ml.data.url_dataset import domain_group, grouped_split_indices


def test_prepare_dataset_deduplicates_offline_and_preserves_real_observations(tmp_path):
    source_path = tmp_path / "PhiUSIIL.csv"
    with source_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["URL", "label", "feature"])
        writer.writeheader()
        writer.writerows([
            {"URL": "https://EXAMPLE.com:443/a#first", "label": "1", "feature": "real"},
            {"URL": "https://example.com/a#second", "label": "1", "feature": "real"},
            {"URL": "http://fake-login.xyz/verify", "label": "0", "feature": "real"},
            {"URL": "https://mixed.example.org/", "label": "1", "feature": "real"},
            {"URL": "https://mixed.example.org/#other", "label": "0", "feature": "real"},
            {"URL": "", "label": "1", "feature": "real"},
        ])
    output_path = tmp_path / "labeled_urls.csv"

    manifest = prepare_dataset(source_path, output_path)

    with output_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["url"] for row in rows] == [
        "https://example.com/a#first",
        "http://fake-login.xyz/verify",
    ]
    assert [row["label"] for row in rows] == ["0", "1"]
    assert all(row["source"] == "uci_phiusiil_967" for row in rows)
    assert manifest["provenance"]["source_to_training_label_mapping"] == {
        "0": 1,
        "1": 0,
    }
    assert manifest["provenance"]["derived_rows"] == 2
    assert manifest["provenance"]["duplicate_url_rows_removed"] == 1
    assert manifest["provenance"]["conflicting_normalized_url_groups_removed"] == 1
    assert manifest["provenance"]["conflicting_normalized_url_rows_removed"] == 2
    assert manifest["provenance"]["invalid_url_rows"] == 1
    assert manifest["provenance"]["training_samples_are_live_url_fetches"] is False
    assert output_path.with_suffix(".manifest.json").is_file()


def test_prepare_dataset_requires_a_local_source_file(tmp_path):
    missing = tmp_path / "missing.csv"

    try:
        prepare_dataset(missing, tmp_path / "out.csv")
    except FileNotFoundError as exc:
        assert "--source" in str(exc)
    else:
        raise AssertionError("missing local source must fail")


def test_manifest_is_valid_json(tmp_path):
    source_path = tmp_path / "source.csv"
    source_path.write_text(
        "URL,label\nhttps://legitimate.example/,1\nhttp://phish.test/,0\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "prepared.csv"

    prepare_dataset(source_path, output_path)

    manifest = json.loads(output_path.with_suffix(".manifest.json").read_text())
    assert manifest["dataset_summary"]["rows"] == 2


def test_grouped_split_keeps_each_registrable_domain_in_one_partition():
    urls = [
        "https://one.example.com/a",
        "https://two.example.com/b",
        "http://phish-one.com/login",
        "https://phish-two.com/verify",
        "https://legit-one.org/",
        "https://legit-two.org/",
        "http://phish-three.net/login",
        "http://phish-four.net/verify",
        "https://legit-three.net/",
        "https://legit-four.net/",
    ]
    labels = np.array([0, 0, 1, 1, 0, 0, 1, 1, 0, 0])

    splits = grouped_split_indices(urls, labels, proportions=(0.6, 0.2, 0.2))
    domains_by_split = [
        {domain_group(urls[index]) for index in indices}
        for indices in splits
    ]
    assert all(
        not domains_by_split[left].intersection(domains_by_split[right])
        for left in range(len(domains_by_split))
        for right in range(left + 1, len(domains_by_split))
    )
    assert all(set(np.unique(labels[indices])) == {0, 1} for indices in splits)
