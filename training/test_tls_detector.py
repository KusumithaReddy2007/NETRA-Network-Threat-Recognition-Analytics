from __future__ import annotations

from app.services.tls.tls_detector import (
    TLSBehaviorEngine,
)
from app.services.tls.tls_reader import (
    ZeekTLSRecord,
)


def make_record(
    *,
    timestamp: float,
    uid: str,
    anomalous: bool,
) -> ZeekTLSRecord:

    if anomalous:
        fields = {
            "ts": str(timestamp),
            "uid": uid,
            "id.orig_h": "10.10.10.10",
            "id.orig_p": "50000",
            "id.resp_h": "192.0.2.10",
            "id.resp_p": "8443",
            "version": "SSLv3",
            "cipher": "",
            "curve": "",
            "server_name": "",
            "resumed": "",
            "next_protocol": "",
            "ssl_history": "",
            "ja4": "synthetic-ja4",
            "ja4s": "",
        }

    else:
        fields = {
            "ts": str(timestamp),
            "uid": uid,
            "id.orig_h": "172.28.137.120",
            "id.orig_p": "50000",
            "id.resp_h": "104.20.23.154",
            "id.resp_p": "443",
            "version": "TLSv13",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "curve": "X25519MLKEM768",
            "server_name": "example.com",
            "resumed": "F",
            "next_protocol": "",
            "ssl_history": "CsiI",
            "ja4": (
                "t13d3013h2_"
                "1d37bd780c83_"
                "8537cf56674e"
            ),
            "ja4s": (
                "t130200_1302_"
                "234ea6891581"
            ),
        }

    return ZeekTLSRecord(
        fields=fields
    )


def test_benign_tls_does_not_trigger():
    engine = TLSBehaviorEngine()

    results = []

    for i in range(12):
        results.append(
            engine.analyze(
                make_record(
                    timestamp=1000.0 + i * 2.0,
                    uid=f"BENIGN-{i}",
                    anomalous=False,
                )
            )
        )

    assert not any(
        result.triggered
        for result in results
    )


def test_anomalous_tls_triggers():
    engine = TLSBehaviorEngine(
        minimum_events=3,
        score_threshold=70.0,
        minimum_supporting_signals=3,
    )

    results = []

    for i in range(8):
        results.append(
            engine.analyze(
                make_record(
                    timestamp=2000.0 + i * 0.5,
                    uid=f"ANOMALY-{i}",
                    anomalous=True,
                )
            )
        )

    assert any(
        result.triggered
        for result in results
    )

    triggered = [
        result
        for result in results
        if result.triggered
    ]

    assert triggered[-1].score >= 70.0
    assert (
        triggered[-1].evidence[
            "supporting_signal_count"
        ]
        >= 3
    )
