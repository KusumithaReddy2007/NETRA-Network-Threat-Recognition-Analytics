from backend.app.services.ingestion.netra_stream_engine import NetraStreamEngine
from backend.app.services.dns.dns_reader import ZeekDNSTSVReader

engine = NetraStreamEngine()

dns_count = 0
alerts = []

reader = ZeekDNSTSVReader("data/zeek/dns.log")

for record in reader:
    result = engine.process_dns(record)
    dns_count += 1

    if result["behavioral_detections"]:
        alerts.append(result)

print("=" * 70)
print("NETRA UNIFIED DNS STREAM TEST")
print("=" * 70)
print("DNS records processed:", dns_count)
print("DNS alerts:", len(alerts))

for alert in alerts[:10]:
    print()
    print("QUERY:", alert["query"])
    print("SOURCE:", alert["source_ip"])
    print("DETECTIONS:", alert["behavioral_detections"])
