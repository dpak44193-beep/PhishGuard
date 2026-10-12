"""Offline URL normalization and leakage-resistant dataset splitting."""
from __future__ import annotations

import ipaddress
import random
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    import numpy as np

import tldextract

_PUBLIC_SUFFIX = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def normalize_url(url: str, *, drop_fragment: bool = False) -> str | None:
    """Normalize an HTTP(S) URL offline; optionally remove fragment for deduplication."""
    value = url.strip()
    if not value:
        return None
    if any(character.isspace() or ord(character) < 32 for character in value):
        return None
    if "://" not in value:
        value = f"http://{value}"

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError):
        return None

    if scheme not in {"http", "https"} or not host:
        return None

    try:
        address = ipaddress.ip_address(host)
        host = f"[{host}]" if address.version == 6 else host
    except ValueError:
        labels = host.split(".")
        if (
            len(host) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or any(not (character.isascii() and (character.isalnum() or character == "-")) for character in label)
                for label in labels
            )
        ):
            return None

    user_info = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = f"{user_info}{host}"
    if port is not None and not default_port:
        netloc += f":{port}"

    fragment = "" if drop_fragment else parsed.fragment
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, fragment))


def domain_group(url: str) -> str:
    """Return the registrable domain, honoring private hosting suffixes offline."""
    normalized = normalize_url(url)
    if normalized is None:
        raise ValueError(f"URL has no valid HTTP(S) host: {url!r}")
    host = (urlsplit(normalized).hostname or "").lower().rstrip(".")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        extracted = _PUBLIC_SUFFIX(host)
        return extracted.top_domain_under_public_suffix or host


def grouped_split_indices(
    urls: list[str],
    labels: np.ndarray,
    *,
    proportions: tuple[float, ...] = (0.70, 0.15, 0.15),
    random_state: int = 42,
) -> tuple[np.ndarray, ...]:
    """Split by registrable domain while approximating requested sizes and class ratios."""
    import numpy as np

    if len(urls) != len(labels) or len(proportions) < 2:
        raise ValueError("URLs, labels, and at least two split proportions are required.")
    if any(value <= 0 for value in proportions) or not np.isclose(sum(proportions), 1.0):
        raise ValueError("Split proportions must be positive and sum to 1.")

    labels = np.asarray(labels)
    grouped_indices: dict[str, list[int]] = {}
    for index, url in enumerate(urls):
        grouped_indices.setdefault(domain_group(url), []).append(index)
    if len(grouped_indices) < len(proportions):
        raise ValueError("Not enough distinct registrable domains for a group-disjoint split.")

    target_phishing_rate = float(np.mean(labels))
    best: tuple[float, tuple[np.ndarray, ...]] | None = None

    for attempt in range(128):
        group_order = list(grouped_indices)
        random.Random(random_state + attempt).shuffle(group_order)
        split_lists: list[list[int]] = [[] for _ in proportions]
        split_groups_working: list[set[str]] = [set() for _ in proportions]
        group_cursor = 0
        for split_number, target_size in enumerate(proportions):
            remaining_splits = len(proportions) - split_number - 1
            target_count = len(labels) * target_size
            current_count = 0
            while group_cursor < len(group_order) - remaining_splits:
                group_name = group_order[group_cursor]
                group_rows = grouped_indices[group_name]
                if (
                    remaining_splits
                    and split_lists[split_number]
                    and current_count + len(group_rows) > target_count
                    and abs(current_count - target_count)
                    <= abs(current_count + len(group_rows) - target_count)
                ):
                    break
                split_lists[split_number].extend(group_rows)
                split_groups_working[split_number].add(group_name)
                current_count += len(group_rows)
                group_cursor += 1
                if remaining_splits and current_count >= target_count:
                    break
        split_indices = [
            np.asarray(indices, dtype=int) for indices in split_lists
        ]

        if any(len(indices) == 0 for indices in split_indices):
            continue
        if any(set(np.unique(labels[indices])) != set(np.unique(labels)) for indices in split_indices):
            continue

        if sum(map(len, split_groups_working)) != len(grouped_indices):
            raise RuntimeError("A registrable domain leaked across dataset splits.")

        size_error = sum(
            abs(len(indices) / len(labels) - target)
            for indices, target in zip(split_indices, proportions)
        )
        class_error = sum(
            abs(float(np.mean(labels[indices])) - target_phishing_rate)
            for indices in split_indices
        )
        score = size_error + 10 * class_error
        if best is None or score < best[0]:
            best = (score, tuple(split_indices))

    if best is None:
        raise ValueError(
            "Could not make a group-disjoint split containing both labels in every "
            "partition. Add more independently sourced domains or adjust the split."
        )
    return best[1]
