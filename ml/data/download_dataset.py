"""Prepare the documented PhiUSIIL corpus locally without visiting sample URLs.

Download the source CSV manually from the UCI page linked in ``SOURCE``. This
script only reads that local file and writes a deduplicated, provenance-bearing
URL CSV plus a JSON manifest; it never fetches or opens any URL in the corpus.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import tldextract

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.data.url_dataset import domain_group, normalize_url

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = {
    "kind": "uci_phiusiil_derived",
    "source_name": "PhiUSIIL Phishing URL (Website)",
    "source_url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
    "source_doi": "https://doi.org/10.1016/j.cose.2023.103545",
    "source_creator": ["Arvind Prasad", "Shalini Chandra"],
    "source_dataset_creation_year": 2024,
    "source_repository_last_updated": "2024-05-12",
    "source_observation_collection_window": None,
    "source_observation_collection_note": (
        "UCI describes the URLs as mostly latest but gives no precise "
        "per-observation collection period."
    ),
    "license": "CC BY 4.0",
    "license_url": "https://creativecommons.org/licenses/by/4.0/",
    "attribution": (
        "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) "
        "[Dataset]. UCI Machine Learning Repository. "
        "https://doi.org/10.1016/j.cose.2023.103545"
    ),
    "source_label_definition": {"0": "phishing", "1": "legitimate"},
    "training_label_definition": {"0": "legitimate", "1": "phishing"},
    "source_to_training_label_mapping": {"0": 1, "1": 0},
    "labels_are_source_annotations": True,
    "training_samples_are_live_url_fetches": False,
}
SOURCE_ID = "uci_phiusiil_967"
DEFAULT_SOURCE = REPO_ROOT / "PhiUSIIL_Phishing_URL_Dataset.csv"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "raw" / "labeled_urls.csv"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def prepare_dataset(source_path: Path, output_path: Path) -> dict[str, Any]:
    """Normalize source URLs, remove duplicate/conflicting identities, and report provenance."""
    if not source_path.is_file():
        raise FileNotFoundError(
            f"Source CSV not found: {source_path}. Download PhiUSIIL from "
            f"{SOURCE['source_url']} and pass its local path with --source."
        )

    records: dict[str, dict[str, Any]] = {}
    key_labels: dict[str, set[int]] = defaultdict(set)
    source_label_counts: Counter[str] = Counter()
    key_counts: Counter[str] = Counter()
    missing_cells: Counter[str] = Counter()
    invalid_url_rows = 0
    invalid_label_rows = 0
    source_rows = 0
    source_columns: list[str] = []

    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        source_columns = list(reader.fieldnames or [])
        fields = {name.lower(): name for name in source_columns}
        if "url" not in fields or "label" not in fields:
            raise ValueError("PhiUSIIL source must contain URL and label columns.")
        for source_row, row in enumerate(reader, start=2):
            source_rows += 1
            for name, value in row.items():
                if value is None or not value.strip():
                    missing_cells[name or "<unnamed>"] += 1

            raw_url = (row.get(fields["url"]) or "").strip()
            raw_label = (row.get(fields["label"]) or "").strip()
            if raw_label not in {"0", "1"}:
                invalid_label_rows += 1
                continue
            source_label_counts[raw_label] += 1

            normalized = normalize_url(raw_url)
            if normalized is None:
                invalid_url_rows += 1
                continue

            training_label = 1 if raw_label == "0" else 0
            dedup_key = normalize_url(normalized, drop_fragment=True)
            assert dedup_key is not None
            key_labels[dedup_key].add(training_label)
            key_counts[dedup_key] += 1
            if dedup_key not in records:
                records[dedup_key] = {
                    "url": normalized,
                    "label": training_label,
                    "registrable_domain": domain_group(normalized),
                    "source": SOURCE_ID,
                    "source_label": int(raw_label),
                    "source_row": source_row,
                }

    conflicting_keys = {key for key, labels in key_labels.items() if len(labels) > 1}
    conflicting_rows_removed = sum(key_counts[key] for key in conflicting_keys)
    unique_records = [
        record for key, record in records.items() if key not in conflicting_keys
    ]
    duplicate_rows_removed = (
        source_rows - invalid_label_rows - invalid_url_rows
        - conflicting_rows_removed - len(unique_records)
    )
    if not unique_records:
        raise ValueError("No valid, non-conflicting URL rows were found in the source.")

    domain_labels: dict[str, set[int]] = defaultdict(set)
    for record in unique_records:
        domain_labels[record["registrable_domain"]].add(record["label"])

    label_counts = Counter(record["label"] for record in unique_records)
    domains_by_label = {
        "0_legitimate": len({
            record["registrable_domain"] for record in unique_records if record["label"] == 0
        }),
        "1_phishing": len({
            record["registrable_domain"] for record in unique_records if record["label"] == 1
        }),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_columns = [
        "url", "label", "registrable_domain", "source", "source_label", "source_row"
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_columns)
        writer.writeheader()
        writer.writerows(unique_records)

    overlap_count = sum(len(labels) > 1 for labels in domain_labels.values())
    provenance = {
        **SOURCE,
        "source_file": _manifest_path(source_path),
        "source_file_sha256": _sha256(source_path),
        "derived_file": _manifest_path(output_path),
        "derived_file_sha256": _sha256(output_path),
        "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_rows": source_rows,
        "source_columns": len(source_columns),
        "source_missing_cells": sum(missing_cells.values()),
        "source_missing_cells_by_column": dict(sorted(missing_cells.items())),
        "invalid_url_rows": invalid_url_rows,
        "invalid_label_rows": invalid_label_rows,
        "source_label_counts": dict(sorted(source_label_counts.items())),
        "conflicting_normalized_url_groups_removed": len(conflicting_keys),
        "conflicting_normalized_url_rows_removed": conflicting_rows_removed,
        "duplicate_url_rows_removed": duplicate_rows_removed,
        "derived_rows": len(unique_records),
        "derived_label_counts": {
            "0_legitimate": label_counts[0],
            "1_phishing": label_counts[1],
        },
        "registrable_domain_groups": len(domain_labels),
        "registrable_domains_by_label": domains_by_label,
        "domains_with_both_labels": overlap_count,
        "campaign_identifiers_available": False,
        "split_group_key": "registrable_domain",
        "registrable_domain_extractor": {
            "package": "tldextract",
            "version": tldextract.__version__,
            "include_private_suffixes": True,
            "network_suffix_list_fetch": False,
        },
        "final_evaluation_eligible": True,
        "limitations": [
            "UCI provides no precise collection window for individual observations.",
            "Labels are inherited from the authors; this preparation does not re-verify site content.",
            "A registrable domain may have both labels; rows for each domain stay in one split.",
            "No campaign identifiers are supplied, so campaign overlap cannot be independently measured.",
            "URL strings are analyzed offline; none is visited, resolved, or crawled.",
        ],
    }
    manifest = {
        "schema_version": 1,
        "provenance": provenance,
        "dataset_summary": {
            "rows": len(unique_records),
            "columns": output_columns,
            "missing_cells_in_source": sum(missing_cells.values()),
            "label_counts": provenance["derived_label_counts"],
            "deduplication": {
                "normalization": (
                    "Lowercase scheme and host, IDNA-normalize host, remove default "
                    "port, add root slash; preserve URL paths, queries, and fragments "
                    "in output; ignore fragments only in duplicate identity."
                ),
                "conflicting_label_url_groups_removed": len(conflicting_keys),
                "duplicate_rows_removed": duplicate_rows_removed,
            },
            "domain_overlap": {
                "group_key": "registrable_domain using bundled Public Suffix List snapshot",
                "domains_with_both_labels": overlap_count,
                "campaign_overlap": "not measurable; source has no campaign IDs",
            },
        },
    }
    manifest_path = output_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    report_path = None
    if output_path.resolve() == DEFAULT_OUTPUT.resolve():
        report_path = Path(__file__).resolve().parent / "processed" / "real_dataset_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    log.info(
        "Prepared %s rows (%s legitimate, %s phishing); removed %s exact duplicates "
        "and %s conflicting URL groups.",
        len(unique_records), label_counts[0], label_counts[1],
        duplicate_rows_removed, len(conflicting_keys),
    )
    log.info("CSV: %s", output_path)
    log.info("Manifest: %s", manifest_path)
    if report_path is not None:
        log.info("Inventory report: %s", report_path)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare the local PhiUSIIL URL dataset without visiting sample URLs."
    )
    parser.add_argument(
        "--source", type=Path, default=DEFAULT_SOURCE,
        help="Local UCI PhiUSIIL source CSV (no source download is performed).",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        prepare_dataset(args.source, args.output)
    except (FileNotFoundError, ValueError, OSError, csv.Error) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
