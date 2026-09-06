from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any


DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass
class DNSFeatures:
    query: str

    query_length: int
    label_count: int
    longest_label_length: int
    subdomain_depth: int

    digit_ratio: float
    alphabetic_ratio: float
    alphanumeric_ratio: float
    unique_char_ratio: float

    entropy: float
    average_label_entropy: float
    max_label_entropy: float

    vowel_ratio: float
    consonant_ratio: float

    hyphen_ratio: float
    underscore_ratio: float

    numeric_label_count: int
    hex_character_ratio: float

    repeated_character_ratio: float
    max_character_run: int
    unique_bigram_ratio: float

    suspicious_tld: bool

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length

        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def _max_character_run(value: str) -> int:
    if not value:
        return 0

    best = 1
    current = 1

    for previous, current_char in zip(value, value[1:]):
        if current_char == previous:
            current += 1
            best = max(best, current)
        else:
            current = 1

    return best


def _unique_bigram_ratio(value: str) -> float:
    if len(value) < 2:
        return 0.0

    bigrams = [
        value[index:index + 2]
        for index in range(len(value) - 1)
    ]

    return len(set(bigrams)) / len(bigrams)


def extract_dns_features(query: str) -> DNSFeatures:
    clean_query = (
        str(query)
        .strip()
        .lower()
        .rstrip(".")
    )

    labels = [
        label
        for label in clean_query.split(".")
        if label
    ]

    longest_label = max(
        (len(label) for label in labels),
        default=0,
    )

    chars = "".join(labels)

    length = len(chars)

    digit_count = sum(
        char.isdigit()
        for char in chars
    )

    alphabetic_count = sum(
        char.isalpha()
        for char in chars
    )

    alphanumeric_count = sum(
        char.isalnum()
        for char in chars
    )

    vowel_count = sum(
        char in "aeiou"
        for char in chars
    )

    consonant_count = sum(
        char.isalpha() and char not in "aeiou"
        for char in chars
    )

    hyphen_count = chars.count("-")
    underscore_count = chars.count("_")

    unique_characters = len(set(chars))

    numeric_labels = sum(
        1
        for label in labels
        if label.isdigit()
    )

    hex_characters = sum(
        char in "0123456789abcdef"
        for char in chars
    )

    repeated_adjacent = sum(
        1
        for a, b in zip(chars, chars[1:])
        if a == b
    )

    label_entropies = [
        shannon_entropy(label)
        for label in labels
        if label
    ]

    average_label_entropy = (
        sum(label_entropies) / len(label_entropies)
        if label_entropies
        else 0.0
    )

    max_label_entropy = max(
        label_entropies,
        default=0.0,
    )

    tld = labels[-1] if labels else ""

    suspicious_tlds = {
        "zip",
        "top",
        "click",
        "work",
        "loan",
        "country",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
    }

    return DNSFeatures(
        query=clean_query,

        query_length=length,
        label_count=len(labels),
        longest_label_length=longest_label,
        subdomain_depth=max(len(labels) - 1, 0),

        digit_ratio=_ratio(
            digit_count,
            length,
        ),

        alphabetic_ratio=_ratio(
            alphabetic_count,
            length,
        ),

        alphanumeric_ratio=_ratio(
            alphanumeric_count,
            length,
        ),

        unique_char_ratio=_ratio(
            unique_characters,
            length,
        ),

        entropy=shannon_entropy(chars),

        average_label_entropy=average_label_entropy,
        max_label_entropy=max_label_entropy,

        vowel_ratio=_ratio(
            vowel_count,
            length,
        ),

        consonant_ratio=_ratio(
            consonant_count,
            length,
        ),

        hyphen_ratio=_ratio(
            hyphen_count,
            length,
        ),

        underscore_ratio=_ratio(
            underscore_count,
            length,
        ),

        numeric_label_count=numeric_labels,

        hex_character_ratio=_ratio(
            hex_characters,
            length,
        ),

        repeated_character_ratio=_ratio(
            repeated_adjacent,
            max(length - 1, 1),
        ),

        max_character_run=_max_character_run(chars),

        unique_bigram_ratio=_unique_bigram_ratio(chars),

        suspicious_tld=tld in suspicious_tlds,
    )


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
