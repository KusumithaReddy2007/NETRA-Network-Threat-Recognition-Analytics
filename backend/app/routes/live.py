from __future__ import annotations

from collections import deque
from pathlib import Path
from time import perf_counter
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.services.ingestion.flow_normalizer import (
    normalize_connection,
)
from app.services.ingestion.netra_stream_engine import (
    NetraStreamEngine,
)
from app.services.ingestion.zeek_reader import (
    ZeekTSVReader,
)


router = APIRouter(
    prefix="/live",
    tags=["Live Monitoring"],
)


BASE_DIR = Path(__file__).resolve().parents[3]

LIVE_ZEEK_DIR = (
    BASE_DIR
    / "data"
    / "live_zeek"
)

CONN_LOG_PATH = (
    LIVE_ZEEK_DIR
    / "conn.log"
)


_live_engine = NetraStreamEngine()

_processed_uids: set[str] = set()

_recent_events = deque(
    maxlen=500,
)

_recent_alerts = deque(
    maxlen=200,
)


def _read_live_flows(
    max_records: int,
) -> list[dict[str, Any]]:

    if not CONN_LOG_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Live Zeek conn.log not found: "
                f"{CONN_LOG_PATH}"
            ),
        )

    records = []

    reader = ZeekTSVReader(
        CONN_LOG_PATH
    )

    for record in reader:

        uid = str(
            record.fields.get(
                "uid",
                "",
            )
            or ""
        ).strip()

        if not uid:
            continue

        if uid in _processed_uids:
            continue

        _processed_uids.add(uid)

        flow = normalize_connection(
            record
        )

        result = _live_engine.process_flow(
            flow
        )

        event = {
            "event_type": "flow",
            "flow_id": flow.flow_id,
            "timestamp": flow.timestamp,
            "source_ip": flow.src_ip,
            "source_port": flow.src_port,
            "destination_ip": flow.dst_ip,
            "destination_port": flow.dst_port,
            "protocol": flow.protocol,
            "service": flow.service,
            "duration": flow.duration,
            "orig_bytes": flow.orig_bytes,
            "resp_bytes": flow.resp_bytes,
            "orig_packets": flow.orig_pkts,
            "resp_packets": flow.resp_pkts,
            "conn_state": flow.conn_state,
            "behavioral_detections": result.get(
                "behavioral_detections",
                [],
            ),
            "alerts": result.get(
                "alerts",
                [],
            ),
        }

        _recent_events.appendleft(
            event
        )

        for alert in event["alerts"]:
            _recent_alerts.appendleft(
                alert
            )

        records.append(
            event
        )

        if len(records) >= max_records:
            break

    return records


@router.get("/status")
def live_status():

    return {
        "status": "online"
        if CONN_LOG_PATH.exists()
        else "waiting",
        "zeek_log": str(
            CONN_LOG_PATH
        ),
        "zeek_log_exists": (
            CONN_LOG_PATH.exists()
        ),
        "processed_flows": len(
            _processed_uids
        ),
        "cached_events": len(
            _recent_events
        ),
        "cached_alerts": len(
            _recent_alerts
        ),
    }


@router.post("/poll")
def poll_live_network(
    max_records: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
):

    start = perf_counter()

    new_events = _read_live_flows(
        max_records
    )

    elapsed = (
        perf_counter() - start
    )

    alerts = []

    for event in new_events:
        alerts.extend(
            event.get(
                "alerts",
                [],
            )
        )

    return {
        "status": "success",
        "message": (
            "Live network telemetry processed"
        ),
        "live_statistics": {
            "new_flows": len(
                new_events
            ),
            "total_processed_flows": len(
                _processed_uids
            ),
            "new_alerts": len(
                alerts
            ),
            "total_alerts": len(
                _recent_alerts
            ),
            "processing_time_seconds": round(
                elapsed,
                4,
            ),
            "flows_per_second": round(
                len(new_events) / elapsed,
                2,
            )
            if elapsed > 0
            else 0.0,
        },
        "events": new_events,
        "alerts": alerts,
    }


@router.get("/events")
def get_live_events(
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
    ),
):

    return {
        "status": "success",
        "events": list(
            _recent_events
        )[:limit],
    }


@router.get("/alerts")
def get_live_alerts(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
):

    return {
        "status": "success",
        "alerts": list(
            _recent_alerts
        )[:limit],
    }


@router.post("/reset")
def reset_live_monitor():

    _processed_uids.clear()

    _recent_events.clear()

    _recent_alerts.clear()

    return {
        "status": "success",
        "message": (
            "Live monitoring state reset"
        ),
    }

