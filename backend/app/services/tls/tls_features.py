from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TLSFeatures:
    version: str
    cipher: str
    curve: str
    server_name: str
    resumed: bool
    next_protocol: str
    ssl_history: str

    # JA4+ fingerprint metadata
    ja4: str
    ja4s: str
    has_ja4: bool
    has_ja4s: bool

    destination_port: int
    has_sni: bool
    is_tls13: bool
    is_tls12: bool
    unusual_port: bool
    handshake_anomaly: bool


def _clean(value: object) -> str:
    if value is None:
        return ""

    value = str(value).strip()

    if value in {"-", "(empty)"}:
        return ""

    return value


def _to_bool(value: object) -> bool:
    return str(value).strip().lower() in {
        "t",
        "true",
        "1",
        "yes",
    }


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_tls_features(
    fields: dict[str, str],
) -> TLSFeatures:

    version = _clean(
        fields.get("version", "")
    )

    cipher = _clean(
        fields.get("cipher", "")
    )

    curve = _clean(
        fields.get("curve", "")
    )

    server_name = _clean(
        fields.get("server_name", "")
    )

    next_protocol = _clean(
        fields.get("next_protocol", "")
    )

    ssl_history = _clean(
        fields.get("ssl_history", "")
    )

    # JA4 / JA4S fields added by the FoxIO Zeek scripts.
    ja4 = _clean(
        fields.get("ja4", "")
    )

    ja4s = _clean(
        fields.get("ja4s", "")
    )

    destination_port = _to_int(
        fields.get("id.resp_p", ""),
        0,
    )

    resumed = _to_bool(
        fields.get("resumed", "")
    )

    has_sni = bool(server_name)
    has_ja4 = bool(ja4)
    has_ja4s = bool(ja4s)

    is_tls13 = version.lower() in {
        "tlsv13",
        "tls1.3",
        "tls13",
    }

    is_tls12 = version.lower() in {
        "tlsv12",
        "tls1.2",
        "tls12",
    }

    unusual_port = (
        destination_port not in {
            443,
            8443,
            9443,
        }
        and destination_port != 0
    )

    handshake_anomaly = (
        not has_sni
        or not cipher
        or not version
    )

    return TLSFeatures(
        version=version,
        cipher=cipher,
        curve=curve,
        server_name=server_name,
        resumed=resumed,
        next_protocol=next_protocol,
        ssl_history=ssl_history,
        ja4=ja4,
        ja4s=ja4s,
        has_ja4=has_ja4,
        has_ja4s=has_ja4s,
        destination_port=destination_port,
        has_sni=has_sni,
        is_tls13=is_tls13,
        is_tls12=is_tls12,
        unusual_port=unusual_port,
        handshake_anomaly=handshake_anomaly,
    )
