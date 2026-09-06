from backend.app.services.dns.dns_detector import DNSBehaviorEngine
from backend.app.services.dns.dns_reader import ZeekDNSRecord


def make_record(ts: float, query: str) -> ZeekDNSRecord:
    return ZeekDNSRecord(
        fields={
            "ts": str(ts),
            "id.orig_h": "10.10.10.50",
            "query": query,
            "qtype_name": "A",
        }
    )


def main():
    engine = DNSBehaviorEngine()

    print("=" * 80)
    print("NETRA DNS BEHAVIORAL DETECTOR — SYNTHETIC TEST")
    print("=" * 80)

    # ---------------------------------------------------------------
    # 1. Benign traffic
    # ---------------------------------------------------------------

    benign_queries = [
        "www.google.com",
        "www.microsoft.com",
        "example.com",
        "github.com",
        "openai.com",
        "www.wikipedia.org",
        "stackoverflow.com",
        "python.org",
    ]

    print("\n[1] BENIGN TRAFFIC")

    for i, query in enumerate(benign_queries):
        record = make_record(
            1000.0 + i * 5.0,
            query,
        )

        detections = engine.analyze(record)

        tunnel = [
            d
            for d in detections
            if d.threat_class == "DNS_TUNNEL"
        ][0]

        print(
            f"{query:35} "
            f"score={tunnel.score:6.2f} "
            f"triggered={tunnel.triggered}"
        )

    # ---------------------------------------------------------------
    # 2. Synthetic DNS tunnelling traffic
    # ---------------------------------------------------------------

    engine = DNSBehaviorEngine()

    print("\n[2] SYNTHETIC DNS TUNNELLING TRAFFIC")

    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )

    for i in range(25):
        # Create a long encoded-looking subdomain.
        payload = ""

        for j in range(70):
            payload += alphabet[
                (i * 17 + j * 13) % len(alphabet)
            ]

        query = (
            payload
            + ".data.example.com"
        )

        record = make_record(
            2000.0 + i * 1.5,
            query,
        )

        detections = engine.analyze(record)

        tunnel = [
            d
            for d in detections
            if d.threat_class == "DNS_TUNNEL"
        ][0]

        print(
            f"query={i + 1:02d} "
            f"length={len(query):3d} "
            f"score={tunnel.score:6.2f} "
            f"triggered={tunnel.triggered} "
            f"signals={tunnel.evidence.get('supporting_signal_count')}"
        )

    # ---------------------------------------------------------------
    # 3. Final result
    # ---------------------------------------------------------------

    print("\n[3] RESULT")

    final = tunnel

    print("Final score:", final.score)
    print("Triggered:", final.triggered)
    print(
        "Supporting signals:",
        final.evidence.get("supporting_signal_count"),
    )

    if final.triggered:
        print("\nPASS: Synthetic DNS tunnelling detected.")
    else:
        print("\nFAIL: Synthetic DNS tunnelling was not detected.")


if __name__ == "__main__":
    main()
