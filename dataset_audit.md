# PhishGuard Dataset Audit

## Source and provenance

The locally available corpus is derived from the UCI Machine Learning Repository's [PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), dataset DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545), by Arvind Prasad and Shalini Chandra. UCI states **CC BY 4.0**; attribution and the license link are retained in the local manifest. The CC BY 4.0 deed permits sharing/adaptation with attribution and without implying endorsement.

| Provenance property | Verified local value |
|---|---|
| Original source file | `PhiUSIIL_Phishing_URL_Dataset.csv` |
| Original source SHA-256 | `748ae7c7a677ac4ffc0eeefbe653dcef1d685b134ad2f5376596b92d79438ba` |
| Prepared CSV | `ml/data/raw/labeled_urls.csv` |
| Prepared CSV SHA-256 | `1db2f5ce060de7b073c96d942ff180423e16a01392240bf33e5ca29bb917b4af` |
| UCI repository donated date recorded by manifest | 2024-03-03 |
| Observation collection window | Not specified by UCI; exact dates unavailable |
| Source labels | `0=phishing`, `1=legitimate` |
| Model labels | `0=legitimate`, `1=phishing` |
| Label verification | Source annotations; this preparation did not revisit URLs |

The source CSV was present and hashed locally during this audit. No URL was fetched, resolved, crawled, or visited.

## Inventory and quality

| Measurement | Result |
|---|---:|
| Source rows / columns | 235,795 / 55 |
| Missing source cells | 0 |
| Invalid URL rows / invalid label rows | 0 / 0 |
| Duplicate source URL rows removed | 1,106 |
| Conflicting normalized URL groups removed | 1 group (2 rows) |
| Prepared records | 234,687 |
| Legitimate | 134,849 (57.47%) |
| Phishing | 99,838 (42.53%) |
| Duplicate exact normalized URLs in prepared corpus | 0 |
| Duplicate normalized identities (fragment ignored) | 0 |
| Registrable domains | 197,708 |
| Domains represented with both labels | 105 |
| Campaign IDs available | No |

Normalization lowercases scheme/host, applies IDNA host normalization, removes default ports, inserts `/` at the root, and ignores URL fragments only for duplicate identity. URLs are retained as strings with source row and label information. A domain carrying both source labels is kept intact and assigned to one split; it is not silently relabeled.

The current artifact `base-model-v3` records the same prepared data hash and 234,687 rows. The default `base-model-v2` records a different derived hash (`ed0ea7f53856f18a43457394ba7f76336fb571c1b6f0c1100b155ac115bc41d8`) and different row, label, domain, and invalid-row counts, despite recording the same original source hash. The old derived CSV is not available, so this v2 training input cannot be reconstructed or its result compared reliably.

## Leakage and representation

The saved v3 split has train/validation/test row counts `164,281 / 35,203 / 35,203`; registrable-domain counts `138,563 / 29,631 / 29,514`; pairwise domain overlap is zero. The distribution remains approximately the corpus-wide class rate in each split.

Exact URL duplicates and normalized URL duplicates are absent from the prepared file. However, duplicate **feature vectors** are expected because 30 lexical measurements omit hostname spelling and identity: the corpus has 52,858 distinct vectors for 234,687 records, and 365 distinct vector buckets contain both labels. The exact vector for `https://example.com/` occurs 46 times and all corresponding source labels are phishing. This confirms a salient blind spot in the current representation. Domain grouping prevents the same registrable domain from crossing splits, but it cannot eliminate feature-vector collisions between different domains or detect campaign overlap.

## Independent legitimate-data research

The [UNB/CIC ISCX-URL-2016 page](https://www.unb.ca/cic/datasets/url-2016.html) documents more than 35,300 benign URLs extracted from Alexa-ranked sites and filtered through VirusTotal, around 10,000 phishing URLs from OpenPhish, and additional spam, malware, and defacement categories. This is a useful candidate for further provenance review, but it is dated to a 2016 research publication, the page does not give row-level observation dates or a redistribution license, and it does not specify a versioned VirusTotal benign-label rule. Alexa ranking is not ground-truth benignity; VirusTotal filtering does not establish a timeless benign label. The dataset is not present locally and was not downloaded or used.

[Tranco](https://tranco-list.eu/) provides reproducible archived domain rankings, not confirmed benign labels. A popularity list must not be converted into ground truth. No second, independently sourced, license- and label-verified URL corpus is available in this checkout; therefore the improved-coverage retraining candidate is blocked.

## Limitations

- UCI observation dates and campaign identifiers are missing, making temporal/campaign holdout impossible.
- Labels are inherited from dataset authors; no current site checks were performed.
- Same-source grouped splitting tests unseen registrable domains within one dataset, not future phishing campaigns or broad real-world accuracy.
- Domain grouping does not remove all correlation between sites, hosting providers, campaigns, or feature patterns.
- The available UCI license permits attribution-based adaptation, but that does not independently validate its ground truth.
