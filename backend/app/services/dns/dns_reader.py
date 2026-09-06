from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class ZeekDNSRecord:
    fields: dict[str, str]


class ZeekDNSTSVReader:
    """
    Incremental reader for Zeek dns.log TSV files.

    Zeek header lines begin with '#'. The reader discovers the
    actual field names from the #fields header instead of assuming
    a fixed column ordering.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[ZeekDNSRecord]:
        if not self.path.exists():
            raise FileNotFoundError(f"DNS log not found: {self.path}")

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
                    separator = "\t" if "\\x09" in line else separator
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
                    values.extend([""] * (len(columns) - len(values)))

                if len(values) > len(columns):
                    values = values[:len(columns)]

                record = dict(zip(columns, values))

                for key, value in record.items():
                    if value in {"-", "(empty)"}:
                        record[key] = ""

                yield ZeekDNSRecord(fields=record)
