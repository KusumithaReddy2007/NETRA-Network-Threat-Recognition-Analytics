from __future__ import annotations

from dataclasses import dataclass


@dataclass
class QUICFeatures:
    version: str
    server_name: str
    client_protocol: str
    history: str
    destination_port: int


def extract_quic_features(fields: dict[str, str]) -> QUICFeatures:
    try:
        destination_port = int(
            fields.get("id.resp_p", 0) or 0
        )
    except (TypeError, ValueError):
        destination_port = 0

    return QUICFeatures(
        version=str(
            fields.get("version", "") or ""
        ),
        server_name=str(
            fields.get("server_name", "") or ""
        ),
        client_protocol=str(
            fields.get("client_protocol", "") or ""
        ),
        history=str(
            fields.get("history", "") or ""
        ),
        destination_port=destination_port,
    )
