# NETRA

## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

NETRA is a passive, AI-assisted network threat detection prototype designed for critical-infrastructure environments where traffic can be observed only in one direction through passive mirroring or data-diode style monitoring.

The system analyzes observed network metadata without contacting the original source or destination and without decrypting protected application payloads.

## Validation & Evidence

### Primary NETRA Flow Detection

Train flows: 170,495
Test flows: 42,624
Accuracy: 99.39%
Macro F1: 96.59%
Weighted F1: 99.41%

### Independent DNS Exfiltration Validation

CIC-Bell DNS-EXF-2021 is maintained as external validation evidence and does not replace or modify the production NETRA DNS detector.

Heavy independent evaluation:
Accuracy: 85.29%
Precision: 77.96%
Recall: 99.27%
F1: 87.33%
False-positive rate: 29.29%

### Encrypted Traffic Detection

TLS and QUIC analysis uses metadata only. Payload decryption is disabled.

TQH-C2 TLS replay: 8 records, 1 BOT_C2 alert, confidence 89.99.

Real QUIC replay: 1 record, 0 alerts.

### Streaming Performance

Approximately 103.79 flows/second, 9.62 ms average latency, 19.78 ms P95 latency, 0 dropped flows.

### Passive-Only Design

NETRA is designed for read-only/passive observation and does not require active probing, endpoint contact, or mitigation commands.

### Project Status

NETRA is a functional SIH prototype demonstrating passive ingestion, streaming feature extraction, machine-learning inference, behavioral threat detection, standardized alerts, and analyst-facing visualization for unidirectional IP traffic.
