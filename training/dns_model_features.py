from __future__ import annotations

from collections.abc import Iterable

from backend.app.services.dns.dns_features import (
    DNSFeatures,
    extract_dns_features,
)


NUMERIC_FEATURE_NAMES = [
    "query_length",
    "label_count",
    "longest_label_length",
    "subdomain_depth",
    "digit_ratio",
    "alphabetic_ratio",
    "alphanumeric_ratio",
    "unique_char_ratio",
    "entropy",
    "average_label_entropy",
    "max_label_entropy",
    "vowel_ratio",
    "consonant_ratio",
    "hyphen_ratio",
    "underscore_ratio",
    "numeric_label_count",
    "hex_character_ratio",
    "repeated_character_ratio",
    "max_character_run",
    "unique_bigram_ratio",
    "suspicious_tld",
]


def build_numeric_features(
    domains: Iterable[str],
) -> list[list[float]]:
    """
    Canonical DNS numeric features.

    This function deliberately delegates all feature calculation to
    NETRA's runtime DNS feature extractor so training and inference
    cannot silently diverge.
    """

    rows: list[list[float]] = []

    for domain in domains:
        features: DNSFeatures = extract_dns_features(
            str(domain)
        )

        row = [
            features.query_length,
            features.label_count,
            features.longest_label_length,
            features.subdomain_depth,
            features.digit_ratio,
            features.alphabetic_ratio,
            features.alphanumeric_ratio,
            features.unique_char_ratio,
            features.entropy,
            features.average_label_entropy,
            features.max_label_entropy,
            features.vowel_ratio,
            features.consonant_ratio,
            features.hyphen_ratio,
            features.underscore_ratio,
            features.numeric_label_count,
            features.hex_character_ratio,
            features.repeated_character_ratio,
            features.max_character_run,
            features.unique_bigram_ratio,
            int(features.suspicious_tld),
        ]

        rows.append(row)

    return rows


def approximate_ngram_rarity(
    query: str,
    reference_ngrams: dict[str, float] | None = None,
    n: int = 3,
) -> float:
    """
    Estimate character n-gram rarity using an externally learned
    reference distribution.

    No reference model means no fabricated rarity score.
    """

    if not reference_ngrams:
        return 0.0

    clean = (
        str(query)
        .strip()
        .lower()
        .rstrip(".")
    )

    if len(clean) < n:
        return 0.0

    grams = [
        clean[index:index + n]
        for index in range(len(clean) - n + 1)
    ]

    if not grams:
        return 0.0

    rarity_values = [
        1.0 - min(
            max(
                reference_ngrams.get(
                    gram,
                    0.0,
                ),
                0.0,
            ),
            1.0,
        )
        for gram in grams
    ]

    return sum(rarity_values) / len(rarity_values)
