from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ZeekQUICRecord:
    fields: dict[str, str]


def _normalize(value: str) -> str:
    return "" if value in {"-", "(empty)", "(unset)"} else value


class ZeekQUICTSVReader:
    """
    Incremental reader for Zeek quic.log files.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self):
        if not self.path.exists():
            raise FileNotFoundError(self.path)

        fields: list[str] | None = None

        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.rstrip("\n")

                if not line or line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    continue

                if not fields:
                    continue

                values = line.split("\t")

                if len(values) < len(fields):
                    values.extend([""] * (len(fields) - len(values)))

                yield ZeekQUICRecord(
                    fields={
                        key: _normalize(value)
                        for key, value in zip(fields, values)
                    }
                )
