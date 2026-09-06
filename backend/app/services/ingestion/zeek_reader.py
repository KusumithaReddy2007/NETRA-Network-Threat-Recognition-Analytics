from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class ZeekRecord:
    """
    Generic Zeek TSV record.

    Zeek logs contain metadata headers beginning with '#'.
    This reader converts each data line into a dictionary-like object.
    """

    fields: dict[str, str]


class ZeekTSVReader:
    """Read Zeek TSV logs safely and incrementally."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[ZeekRecord]:
        if not self.path.exists():
            raise FileNotFoundError(f"Zeek log not found: {self.path}")

        columns: Optional[list[str]] = None
        separator = "\t"
        unset_value = "-"
        empty_value = "(empty)"

        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\n")

                if not line:
                    continue

                if line.startswith("#separator"):
                    # Zeek's default separator is encoded as \x09.
                    if "\\x09" in line:
                        separator = "\t"
                    continue

                if line.startswith("#set_separator"):
                    continue

                if line.startswith("#empty_field"):
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        empty_value = parts[1].strip()
                    continue

                if line.startswith("#unset_field"):
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        unset_value = parts[1].strip()
                    continue

                if line.startswith("#fields"):
                    columns = line.split("\t")[1:]
                    continue

                if line.startswith("#"):
                    continue

                if columns is None:
                    raise ValueError(
                        f"Zeek log is missing #fields header: {self.path}"
                    )

                values = line.split(separator)

                # Protect against malformed/truncated lines.
                if len(values) < len(columns):
                    values.extend([unset_value] * (len(columns) - len(values)))

                if len(values) > len(columns):
                    values = values[: len(columns)]

                record = {
                    column: value
                    for column, value in zip(columns, values)
                }

                # Normalize Zeek special values.
                for key, value in record.items():
                    if value == empty_value:
                        record[key] = ""
                    elif value == unset_value:
                        record[key] = ""

                yield ZeekRecord(fields=record)
