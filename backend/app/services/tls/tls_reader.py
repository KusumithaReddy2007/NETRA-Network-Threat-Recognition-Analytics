from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class ZeekTLSRecord:
    fields: dict[str, str]


@dataclass
class ZeekConnRecord:
    fields: dict[str, str]


def _normalize_value(value: str) -> str:
    if value in {"-", "(empty)"}:
        return ""
    return value


class ZeekTLSTSVReader:
    """
    Incremental reader for Zeek ssl.log TSV files.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[ZeekTLSRecord]:
        if not self.path.exists():
            raise FileNotFoundError(
                f"TLS log not found: {self.path}"
            )

        columns: Optional[list[str]] = None
        separator = "\t"

        with self.path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            for raw_line in handle:
                line = raw_line.rstrip("\n")

                if not line:
                    continue

                if line.startswith("#separator"):
                    separator = "\t"
                    continue

                if line.startswith("#fields"):
                    columns = line.split("\t")[1:]
                    continue

                if line.startswith("#"):
                    continue

                if columns is None:
                    raise ValueError(
                        f"Missing #fields header in {self.path}"
                    )

                values = line.split(separator)

                if len(values) < len(columns):
                    values.extend(
                        [""] * (
                            len(columns) - len(values)
                        )
                    )

                values = values[:len(columns)]

                record = dict(
                    zip(columns, values)
                )

                record = {
                    key: _normalize_value(value)
                    for key, value in record.items()
                }

                yield ZeekTLSRecord(
                    fields=record
                )


class ZeekConnTSVReader:
    """
    Incremental reader for Zeek conn.log TSV files.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[ZeekConnRecord]:
        if not self.path.exists():
            raise FileNotFoundError(
                f"Connection log not found: {self.path}"
            )

        columns: Optional[list[str]] = None
        separator = "\t"

        with self.path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            for raw_line in handle:
                line = raw_line.rstrip("\n")

                if not line:
                    continue

                if line.startswith("#separator"):
                    separator = "\t"
                    continue

                if line.startswith("#fields"):
                    columns = line.split("\t")[1:]
                    continue

                if line.startswith("#"):
                    continue

                if columns is None:
                    raise ValueError(
                        f"Missing #fields header in {self.path}"
                    )

                values = line.split(separator)

                if len(values) < len(columns):
                    values.extend(
                        [""] * (
                            len(columns) - len(values)
                        )
                    )

                values = values[:len(columns)]

                record = dict(
                    zip(columns, values)
                )

                record = {
                    key: _normalize_value(value)
                    for key, value in record.items()
                }

                yield ZeekConnRecord(
                    fields=record
                )
