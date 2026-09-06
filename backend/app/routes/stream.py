from __future__ import annotations

from pathlib import Path
from time import perf_counter

from fastapi import APIRouter, HTTPException, Query

from app.services.ingestion.netra_stream_engine import (
    NetraStreamEngine,
)
from app.services.dns.dns_reader import (
    ZeekDNSTSVReader,
)
from app.services.tls.tls_reader import (
    ZeekTLSTSVReader,
    ZeekConnTSVReader,
)
from app.services.quic.quic_reader import (
    ZeekQUICTSVReader,
)
from app.services.stream_service import (
    stream_flows,
)


router = APIRouter(
    prefix="/stream",
    tags=["Streaming Detection"],
)


BASE_DIR = Path(__file__).resolve().parents[3]

DNS_LOG_PATH = (
    BASE_DIR
    / "data"
    / "zeek"
    / "dns.log"
)

TLS_LOG_PATH = (
    BASE_DIR
    / "data"
    / "zeek_ja4"
    / "ssl.log"
)

CONN_LOG_PATH = (
    BASE_DIR
    / "data"
    / "zeek_ja4"
    / "conn.log"
)

TQH_TLS_LOG_PATH = (
    BASE_DIR
    / "data"
    / "zeek_tqh_demo"
    / "ssl.log"
)

TQH_CONN_LOG_PATH = (
    BASE_DIR
    / "data"
    / "zeek_tqh_demo"
    / "conn.log"
)

QUIC_LOG_PATH = (
    BASE_DIR
    / "data"
    / "zeek_quic"
    / "quic.log"
)


@router.post("/replay")
def replay_stream(
    max_flows: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
    delay: float = Query(
        default=0.0,
        ge=0.0,
        le=5.0,
    ),
):
    result = stream_flows(
        max_flows=max_flows,
        delay=delay,
    )

    return {
        "status": "success",
        "message": (
            "Network traffic replay completed"
        ),
        "stream_statistics": {
            "total_flows": result[
                "total_flows"
            ],
            "threat_alerts": result[
                "total_alerts"
            ],
            "total_time_seconds": result[
                "total_time_seconds"
            ],
            "flows_per_second": result[
                "flows_per_second"
            ],
        },
        "alerts": result["alerts"],
        "results": result["results"],
    }


@router.post("/dns-replay")
def replay_dns(
    max_records: int = Query(
        default=1000,
        ge=1,
        le=10000,
    ),
):
    """
    Replay Zeek dns.log through NETRA's
    streaming DNS detector.
    """

    if not DNS_LOG_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"DNS log not found: "
                f"{DNS_LOG_PATH}"
            ),
        )

    engine = NetraStreamEngine()

    start = perf_counter()

    records_processed = 0
    alerts = []

    reader = ZeekDNSTSVReader(
        DNS_LOG_PATH
    )

    for record in reader:

        if records_processed >= max_records:
            break

        result = engine.process_dns(
            record
        )

        records_processed += 1

        if result["alerts"]:
            alerts.extend(
                result["alerts"]
            )

    total_time = (
        perf_counter() - start
    )

    records_per_second = (
        records_processed / total_time
        if total_time > 0
        else 0.0
    )

    return {
        "status": "success",
        "message": (
            "Zeek DNS traffic replay completed"
        ),
        "dns_statistics": {
            "records_processed": (
                records_processed
            ),
            "threat_alerts": len(alerts),
            "total_time_seconds": round(
                total_time,
                4,
            ),
            "records_per_second": round(
                records_per_second,
                2,
            ),
        },
        "alerts": alerts,
    }


@router.post("/tls-replay")
def replay_tls(
    max_records: int = Query(
        default=1000,
        ge=1,
        le=10000,
    ),
    source: str = Query(
        default="benign",
        pattern="^(benign|tqh_c2)$",
    ),
):
    """
    Replay Zeek ssl.log through NETRA's TLS metadata detector.

    TLS and connection records are correlated using the Zeek UID.

    Payloads are never decrypted.
    """

    if source == "tqh_c2":
        tls_log_path = TQH_TLS_LOG_PATH
        conn_log_path = TQH_CONN_LOG_PATH
    else:
        tls_log_path = TLS_LOG_PATH
        conn_log_path = CONN_LOG_PATH

    if not tls_log_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"TLS log not found: "
                f"{tls_log_path}"
            ),
        )

    if not conn_log_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Connection log not found: "
                f"{conn_log_path}"
            ),
        )

    start = perf_counter()

    tls_reader = ZeekTLSTSVReader(
        tls_log_path
    )

    conn_reader = ZeekConnTSVReader(
        conn_log_path
    )

    conn_by_uid = {}

    for record in conn_reader:
        uid = str(
            record.fields.get(
                "uid",
                "",
            )
            or ""
        ).strip()

        if uid:
            conn_by_uid[uid] = record.fields

    engine = NetraStreamEngine()

    records_processed = 0
    matched_connection_records = 0
    alerts = []
    detections = []
    latencies = []

    for record in tls_reader:

        if records_processed >= max_records:
            break

        uid = str(
            record.fields.get(
                "uid",
                "",
            )
            or ""
        ).strip()

        conn_fields = conn_by_uid.get(
            uid,
            {},
        )

        if conn_fields:
            matched_connection_records += 1

        result = engine.process_tls(
            record,
            conn_fields,
        )

        records_processed += 1

        detections.extend(
            result["behavioral_detections"]
        )

        latencies.append(
            result["processing_latency_ms"]
        )

        if result["alerts"]:
            alerts.extend(
                result["alerts"]
            )

    total_time = (
        perf_counter() - start
    )

    records_per_second = (
        records_processed / total_time
        if total_time > 0
        else 0.0
    )

    average_latency = (
        sum(latencies) / len(latencies)
        if latencies
        else 0.0
    )

    unique_ja4 = sorted(
        {
            detection["evidence"].get(
                "ja4"
            )
            for detection in detections
            if detection["evidence"].get(
                "ja4"
            )
        }
    )

    unique_ja4s = sorted(
        {
            detection["evidence"].get(
                "ja4s"
            )
            for detection in detections
            if detection["evidence"].get(
                "ja4s"
            )
        }
    )

    return {
        "status": "success",
        "message": (
            "Zeek TLS traffic replay completed"
        ),
        "tls_statistics": {
            "records_processed": (
                records_processed
            ),
            "connection_records_available": (
                len(conn_by_uid)
            ),
            "matched_connection_records": (
                matched_connection_records
            ),
            "threat_alerts": len(alerts),
            "total_time_seconds": round(
                total_time,
                4,
            ),
            "records_per_second": round(
                records_per_second,
                2,
            ),
            "average_processing_latency_ms": round(
                average_latency,
                3,
            ),
            "unique_ja4": unique_ja4,
            "unique_ja4s": unique_ja4s,
            "payload_decryption": False,
        },
        "detections": detections,
        "alerts": alerts,
    }


@router.post("/quic-replay")
def replay_quic(
    max_records: int = Query(
        default=1000,
        ge=1,
        le=10000,
    ),
):
    """
    Replay Zeek quic.log through NETRA's passive QUIC
    metadata detector.

    QUIC payloads are never decrypted.
    """

    if not QUIC_LOG_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"QUIC log not found: "
                f"{QUIC_LOG_PATH}. "
                "Generate it from a QUIC PCAP with Zeek first."
            ),
        )

    start = perf_counter()

    reader = ZeekQUICTSVReader(
        QUIC_LOG_PATH
    )

    engine = NetraStreamEngine()

    records_processed = 0
    detections = []
    alerts = []
    latencies = []

    for record in reader:
        if records_processed >= max_records:
            break

        result = engine.process_quic(record)

        records_processed += 1

        detections.extend(
            result["behavioral_detections"]
        )

        alerts.extend(
            result["alerts"]
        )

        latencies.append(
            result["processing_latency_ms"]
        )

    total_time = perf_counter() - start

    records_per_second = (
        records_processed / total_time
        if total_time > 0
        else 0.0
    )

    average_latency = (
        sum(latencies) / len(latencies)
        if latencies
        else 0.0
    )

    return {
        "status": "success",
        "message": (
            "Zeek QUIC traffic replay completed"
        ),
        "quic_statistics": {
            "records_processed": records_processed,
            "threat_alerts": len(alerts),
            "total_time_seconds": round(
                total_time,
                4,
            ),
            "records_per_second": round(
                records_per_second,
                2,
            ),
            "average_processing_latency_ms": round(
                average_latency,
                3,
            ),
            "payload_decryption": False,
        },
        "detections": detections,
        "alerts": alerts,
    }
