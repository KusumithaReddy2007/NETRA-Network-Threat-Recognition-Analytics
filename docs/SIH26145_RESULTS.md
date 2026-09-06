# NETRA — SIH26145 Master Results

## 1. Dataset Sources

| Source | Type | Purpose |
|---|---|---|
| CIC-IDS2017 | Public benchmark dataset | General flow-based ML |
| CVUT DNS Threats Dataset | Public dataset | DNS/DGA model |
| NETRA realistic PCAP | Lab/realistic benign capture | Passive TLS/DNS/metadata validation |
| NETRA lab PCAPs | Controlled lab-generated data | Streaming and metadata validation |

> Public datasets are not claimed to be official NTRO datasets.

## 2. General ML Result

CIC-IDS2017-based stratified holdout:

- Accuracy: 99.39%
- Macro F1: 96.59%
- Weighted F1: 99.41%

## 3. End-to-End Streaming ML

1,000 flows:

- Correct: 993 / 1,000
- Accuracy: 99.30%
- Throughput: 10.12 flows/sec
- Average latency: 98.61 ms
- P95 latency: 106.72 ms
- Note: this is the earlier 1,000-flow dataset-to-ML-to-alert benchmark.

## 4. DGA Model

CVUT DNS Threats Dataset:

- Precision: 82.87%
- Recall: 84.89%
- F1: 83.87%

## 5. DNS Tunnel Behavioral Detection

- Tunnel sources tested: 16
- Tunnel source recall: 100%
- Negative-source false-positive rate: 0%
- Average detection query: 8.06

## 5A. DNS Record-Type Anomaly Detection

Real DNS baseline:

- Records: 26
- A: 12 (46.15%)
- AAAA: 14 (53.85%)
- Record-type anomaly alerts: 0

Controlled benign mix:

- Queries: 11
- Mixed A/AAAA
- Record-type anomaly alerts: 0

Controlled anomaly:

- Queries: 11
- 8 TXT + 3 A
- Dominant type: TXT
- Dominant ratio: 72.73%
- Confidence: 80.0
- DNS_RECORD_ANOMALY alerts: 4
- Alert schema: PASS

The detector treats unusual record types as contextual evidence rather than declaring an individual type malicious.

## 6. DDoS

Controlled streaming test:

- Source flows: 1,000
- Flow rate: 100 flows/sec
- Detection score: 75
- Detection latency: 0.531 ms
- Result: DETECTED

## 7. C2 Beaconing

Controlled periodic test:

- Events: 12
- Interval: approximately 2 sec
- Periodicity CV: approximately 0
- Score: 100
- Result: DETECTED

## 8. Port Scan

Controlled test:

- 20+ unique destination ports
- 1 destination host
- Score: 100
- Result: DETECTED

CIC-IDS2017 sample:

- PORTSCAN confidence: 99.96%
- Result: CORRECT

## 9. Data Exfiltration

Controlled test:

- Outbound: 2,097,152 bytes
- Inbound: 1,024 bytes
- Ratio: 2048
- Score: 76
- Result: DETECTED

## 10. TLS Metadata

Realistic benign TLS PCAP:

- TLS records: 12
- TLS-to-connection matches: 12/12
- JA4: extracted
- JA4S: extracted
- Payload decryption: false

Automated regression:

- Tests passed: 2/2

Controlled 9444 TLS replay:

- TLS records: 12
- Maximum score: 69.30
- Supporting signals: 4
- Alerts: 0
- Payload decryption: false

This controlled traffic was legitimate lab TLS and is not classified as malware.

## 11. Streaming Engine Benchmark

- Flows processed: 10,000
- Throughput: 103.79 flows/sec
- Average latency: 9.623 ms
- P95 latency: 19.780 ms
- Dropped flows: 0
- Note: this is the latest 10,000-flow lower-level streaming-engine benchmark.
- Window: 10 seconds

## 12. Standard Alert Schema

NETRA standardized alerts contain:

- alert_id
- timestamp
- flow_id
- threat_class
- confidence
- severity
- supporting_evidence

## 13. Remaining Validation

- Quantitative malicious/suspicious TLS benchmark
- Final demonstration and documentation review

## 13A. QUIC Metadata Validation

Real passive Zeek QUIC replay:

- Zeek version: 8.2.2
- Source PCAP: `quicv2-http3-443.pcap`
- QUIC records: 1
- QUIC version: `quicv2`
- Client protocol: `h3`
- Destination port: 443
- NETRA processing latency: approximately 0.05–0.08 ms
- Threat alerts: 0
- Payload decryption: false

Controlled metadata anomaly test:

- Benign case: no alert
- Anomalous case: `QUIC_ANOMALY`
- Score: 100.0
- Supporting signals: 5
- Alert schema: PASS
- Payload decryption: false

This validates passive QUIC metadata ingestion and anomaly detection. It does not claim trained malicious-QUIC classification.

## 14. Reporting Rules

The following results must not be conflated:

1. The 99.39% CIC-IDS2017 result is a stratified holdout result, not an independent temporal/session benchmark.
2. The 99.30% result is a 1,000-flow end-to-end streaming evaluation.
3. The latest measured lower-level streaming-engine benchmark is 103.79 flows/sec over 10,000 flows, with 0 dropped flows.
4. The 10.12 flows/sec result is an earlier 1,000-flow dataset-to-ML-to-alert benchmark; the latest 100-flow replay measured 8.32 flows/sec.
5. The 83.87% DGA F1 is a DNS ML metric.
6. The 100% DNS tunnel result is behavioral source recall, not overall classification accuracy.
7. The TLS lab capture is controlled anomalous/benign TLS traffic, not malware.
8. The controlled QUIC anomaly test is metadata-based anomaly validation, not trained malicious-QUIC classification.

## External TLS C2 Validation — TQH-C2

NETRA was externally evaluated against the public TQH-C2 dataset, TLS profile A (`A_i30_j0`), using the dataset's published `labeled.jsonl` ground truth. The evaluated subset contained 5,320 TLS-observable flows: 2,400 `malicious_c2` and 2,920 `benign`.

The generic TLS anomaly detector alone produced 0% recall on this benchmark. Analysis showed that the malicious TLS C2 traffic exhibited highly regular repeated communication, typically approximately every 30 seconds.

A dedicated metadata-only `TLSC2BeaconEngine` was therefore implemented and evaluated without changing the original TLS anomaly detector thresholds. The rule groups traffic by source, destination, JA4 and JA4S and evaluates repeated events and inter-arrival regularity within a bounded 180-second window.

External benchmark result:

- TP: 2,280
- FN: 120
- FP: 1
- TN: 2,919
- Precision: 99.96%
- Recall: 95.00%
- F1: 97.42%
- False-positive rate: 0.03%

The detector was then integrated into `NetraStreamEngine.process_tls()`. End-to-end integration produced 2,280 malicious `BOT_C2` alerts and 1 benign `BOT_C2` alert, with zero malformed alerts. Generated alerts use the standardized NETRA alert schema and explicitly record `payload_decryption: false`.

Dataset provenance: TQH-C2 is an external public research dataset and is not an NTRO-provided or official SIH26145 dataset.
