from __future__ import annotations

import time
from pathlib import Path

from app.services.ingestion.zeek_reader import ZeekTSVReader
from app.services.ingestion.flow_normalizer import normalize_connection
from app.services.ingestion.netra_stream_engine import NetraStreamEngine


BASE_DIR = Path(__file__).resolve().parents[4]

LIVE_ZEEK_DIR = BASE_DIR / "data" / "live_zeek"

CONN_LOG = LIVE_ZEEK_DIR / "conn.log"


def monitor_live_zeek():
    engine = NetraStreamEngine()

    print("=" * 70)
    print("LIVE NETWORK MONITOR STARTED")
    print(f"Watching: {CONN_LOG}")
    print("=" * 70)

    processed_uids = set()

    while True:

        if not CONN_LOG.exists():
            print("Waiting for conn.log...")
            time.sleep(2)
            continue

        try:

            reader = ZeekTSVReader(CONN_LOG)

            for record in reader:

                uid = record.fields.get("uid", "")

                if not uid or uid in processed_uids:
                    continue

                processed_uids.add(uid)

                flow = normalize_connection(record)

                result = engine.process_flow(flow)

                print("\n" + "=" * 70)
                print("LIVE FLOW DETECTED")
                print("=" * 70)

                print(f"Flow ID: {flow.flow_id}")
                print(f"Source: {flow.src_ip}:{flow.src_port}")
                print(f"Destination: {flow.dst_ip}:{flow.dst_port}")
                print(f"Protocol: {flow.protocol}")
                print(f"Duration: {flow.duration}")

                detections = result.get(
                    "behavioral_detections",
                    []
                )

                alerts = result.get(
                    "alerts",
                    []
                )

                if detections:

                    print("\nDETECTIONS:")

                    for detection in detections:

                        print(
                            f"Threat: "
                            f"{detection.get('threat_class')}"
                        )

                        print(
                            f"Score: "
                            f"{detection.get('score')}"
                        )

                if alerts:

                    print("\n🚨 ALERT GENERATED")

                    for alert in alerts:

                        print(alert)

                else:

                    print("\nStatus: Normal / No Alert")

        except Exception as error:

            print(
                f"Monitor error: {error}"
            )

        time.sleep(1)


if __name__ == "__main__":
    monitor_live_zeek()
