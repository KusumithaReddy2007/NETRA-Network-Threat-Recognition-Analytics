# NETRA — SIH26145 Validation Report

## Problem Statement

**SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

Organization: National Technical Research Organisation (NTRO)

## 1. Validation Scope

NETRA is designed as a passive, read-only cyber-threat detection pipeline for traffic observed through mirrored links or a one-way monitoring/data-diode environment.

The prototype does not:
- send probes to production hosts,
- contact traffic sources or destinations,
- issue mitigation commands,
- decrypt TLS/QUIC payloads.

Detection uses passively derived flow, DNS, TLS and behavioral metadata.

---

## 2. Threat Coverage

| Threat class | Current validation status | Evidence |
|---|---|---|
| DDoS | VERIFIED | Controlled streaming flood detected |
| C2 beaconing | VERIFIED | Periodic-flow benchmark detected |
| DGA | VERIFIED / MODEL VALIDATED | DNS model evaluated on 620,703 test records |
| DNS tunnelling | VERIFIED | Behavioral benchmark detected 16/16 tunnel sources |
| Port scanning | VERIFIED | Controlled scan and CIC-IDS2017 evaluation |
| Data exfiltration | VERIFIED | High outbound/inbound byte-ratio test |
| TLS anomaly / encrypted-session analysis | VERIFIED FOR METADATA PIPELINE | Real PCAP + Zeek + JA4/JA4S + benign/anomaly regression |
| QUIC metadata analysis | VERIFIED | Real Zeek QUIC PCAP → quic.log → NETRA process_quic() + controlled anomaly test |
| DNS record-type anomalies | VERIFIED | Real A/AAAA baseline + controlled TXT-dominance anomaly test |

---

## 3. DDoS Validation

Controlled streaming test:

- Source flow count: 1,000
- Source flow rate: 100.0 flows/sec
- Protocol: TCP
- SYN-like pattern: true
- Destination-source entropy: 0.0
- Detection score: 75.0
- Detection latency: 0.531 ms

**Result: DETECTED**

The test used irregular high-rate traffic to avoid confusing the flood with perfectly periodic C2 beaconing.

---

## 4. C2 Beacon Validation

Controlled periodic-flow test:

- Events: 12
- Approximate interval: 2 seconds
- Periodicity coefficient of variation: 0
- Detection: BOT_C2
- Score: 100

**Result: DETECTED**

The detector uses inter-arrival timing and periodicity rather than relying only on addresses.

---

## 5. Port Scan Validation

Controlled scan test:

- Unique destination ports observed: 20+
- Unique destination hosts: 1
- Detection score: 100

**Result: DETECTED**

A sampled CIC-IDS2017 flow evaluation also produced:

- PORTSCAN confidence: 99.96%
- Classification: CORRECT

---

## 6. Data Exfiltration Validation

Controlled flow test:

- Outbound bytes: 2,097,152
- Inbound bytes: 1,024
- Outbound/inbound ratio: 2048
- Detection score: 76.0

**Result: DETECTED**

The detector uses asymmetric outbound/inbound volume as supporting evidence.

---

## 7. DNS / DGA Validation

### DNS ML model

Independent test set:

- Total test rows: 620,703
- BENIGN: 236,072
- DGA: 383,072
- DNS_TUNNEL: 1,559

DGA metrics:

- Precision: 82.87%
- Recall: 84.89%
- F1: 83.87%

DNS model overall:

- Accuracy: 79.61%
- Macro F1: 57.84%
- Weighted F1: 80.12%

The DNS_TUNNEL ML class had low precision (8.46%), therefore the behavioral DNS-tunnel detector is used as the stronger tunnelling validation component.

### DNS behavioral benchmark

- BENIGN samples: 10,000
- DGA samples: 10,000
- DNS tunnel samples: 1,552
- Negative-source false-positive rate: 0.00%
- DNS tunnel source recall: 100.00%
- Average detection query: 8.06

Interpretation:

This benchmark is a simulated stream evaluation because the source dataset provides domains/classes but does not provide timestamps or source IP addresses.


### DNS record-type anomaly validation

NETRA also evaluates recent `qtype_name` behavior from the passive Zeek DNS stream.

Real DNS baseline:

- Records processed: 26
- A records: 12 (46.15%)
- AAAA records: 14 (53.85%)
- DNS record-type anomaly alerts: 0

Controlled benign record-type mix:

- Queries: 11
- Pattern: mixed A/AAAA
- DNS record-type anomaly alerts: 0

Controlled anomalous record-type test:

- Queries: 11
- Pattern: 8 TXT + 3 A
- Dominant record type: TXT
- Dominant ratio: 72.73%
- Confidence: 80.0%
- DNS_RECORD_ANOMALY alerts: 4
- Alert schema: PASS

TXT is not treated as intrinsically malicious. The detector requires a dominant higher-interest record type within a bounded source window, providing contextual evidence rather than a single-type blacklist.

---

## 8. General ML Flow Model

CIC-IDS2017-based holdout evaluation:

- Training rows: 170,495
- Test rows: 42,624
- Accuracy: 99.39%
- Macro F1: 96.59%
- Weighted F1: 99.41%

Per-class F1:

| Class | F1 |
|---|---:|
| BENIGN | 98.75% |
| BOT | 88.05% |
| BRUTE_FORCE | 99.89% |
| DDOS | 99.96% |
| DOS | 99.78% |
| PORTSCAN | 99.91% |
| WEB_ATTACK | 89.79% |

This evaluation is a per-source-file stratified holdout and should not be described as an independent temporal/session benchmark.

---

## 9. End-to-End Streaming ML Evaluation

Evaluation of 1,000 flows through:

dataset -> preprocessing -> ML inference -> alert generation

Results:

- Flows evaluated: 1,000
- Correct predictions: 993
- Accuracy: 99.30%
- End-to-end throughput: 8.32 flows/sec (latest 100-flow replay)
- Total time: 98.841 sec
- Average latency: 98.613 ms
- P95 latency: 106.721 ms

Per-class F1:

| Class | F1 |
|---|---:|
| BENIGN | 98.35% |
| BOT | 80.00% |
| BRUTE_FORCE | 100.00% |
| DDOS | 100.00% |
| DOS | 99.59% |
| PORTSCAN | 99.79% |
| WEB_ATTACK | 93.33% |

Small-support classes such as BOT and WEB_ATTACK should be interpreted cautiously in this 1,000-flow sample.

---

## 10. Streaming Engine Throughput Benchmark

Independent benchmark of the lower-level streaming detection engine:

- Flows processed: 10,000
- Throughput: 103.79 flows/sec
- Average latency: 9.623 ms
- P95 latency: 19.780 ms
- Dropped flows: 0
- Sliding window: 10 seconds

This is different from the 10.12 flows/sec end-to-end dataset-to-alert benchmark because the two tests measure different processing paths.

---

## 11. TLS / Encrypted Session Validation

### Real benign TLS PCAP

NETRA has a realistic TLS PCAP:

`data/pcap/netra_realistic_test.pcap`

Zeek processing provides TLS and connection metadata including:

- TLS version
- cipher
- curve
- SNI
- TLS history
- JA4
- JA4S
- connection duration
- packet counts
- byte counts

A real replay processed:

- TLS records: 12
- TLS-to-connection matches: 12/12
- Payload decryption: false

### TLS regression validation

Automated regression tests:

- benign TLS does not trigger
- anomalous TLS triggers when multiple suspicious metadata signals are present

Test result:

`2 passed`

### Controlled TLS lab capture

A separate controlled TLS lab PCAP was captured and processed with Zeek.

- PCAP size: approximately 136 KB
- Captured packets: 232
- TLS records decoded: 12
- JA4 generated: `t13i3012h2_1d37bd780c83_8537cf56674e`

The traffic produced scores of approximately 55-59 and did not trigger the 70-point TLS anomaly threshold.

Interpretation:

This was ordinary controlled TLS traffic, not malware. It therefore serves as a useful false-positive/anomaly-threshold check but must not be described as a malicious-TLS benchmark.

**TLS quantitative limitation:** the generic TLS anomaly detector is not presented as a calibrated malware classifier; the separate metadata-only TLS C2 beacon detector has been quantitatively evaluated on the external TQH-C2 benchmark.

---

## 11A. QUIC Metadata Validation

### Real passive QUIC replay

A real QUIC HTTP/3 capture shipped with Zeek was processed through the built-in Zeek QUIC analyzer.

- Zeek version: 8.2.2
- Source PCAP: `quicv2-http3-443.pcap`
- QUIC records produced: 1
- QUIC version: `quicv2`
- Client protocol: `h3`
- Destination port: 443
- NETRA processing latency: approximately 0.05–0.08 ms
- Threat alerts: 0
- Payload decryption: `false`

The benign capture was accepted by the QUIC metadata pipeline without generating an alert.

### Controlled QUIC anomaly test

A metadata-only controlled test was also processed through `NetraStreamEngine.process_quic()`.

- Benign metadata: no alert
- Anomalous metadata: `QUIC_ANOMALY`
- Anomaly score: 100.0
- Supporting signals: 5
- Alert schema: PASS
- Payload decryption: `false`

This validates passive QUIC metadata ingestion and anomaly detection. It is not presented as a trained malicious-QUIC classifier.

## 12. Standardized Alert Schema

NETRA uses a common alert construction path for behavioral detections.

Alert fields include:

- alert_id
- timestamp
- flow_id
- threat_class
- confidence
- severity
- supporting_evidence

The same alert service is used for flow and behavioral detections including DDoS, port scan, C2, exfiltration, DNS and TLS anomaly alerts.

---

## 13. Passive / Metadata-Only Constraint

NETRA is designed to operate without:

- active probing,
- source/destination re-contact,
- mitigation commands,
- TLS payload decryption.

TLS detection uses metadata such as JA4/JA4S, TLS version, SNI availability, packet/byte information, timing and connection context.

---

## 14. Current Limitations

1. The generic TLS anomaly detector is not presented as a calibrated malware classifier; the dedicated metadata-only TLS C2 beacon detector has been quantitatively evaluated on the external TQH-C2 benchmark.
2. DNS_TUNNEL ML classification has low precision and is therefore not presented as the primary tunnelling detector; the behavioral DNS-tunnel detector is the stronger prototype component.
3. The 99.39% general ML holdout result is not an independent temporal/session benchmark.
4. The controlled QUIC anomaly test demonstrates metadata anomaly detection, not trained malicious-QUIC classification.
5. Throughput measurements are prototype-environment measurements and are not production-capacity claims.

---

## 15. Current SIH Readiness

### Strongly demonstrated
- Passive/read-only architecture
- Streaming flow processing
- DDoS detection
- C2 beaconing detection
- Port scanning detection
- Data exfiltration detection
- DGA model
- DNS tunnelling behavioral detection
- DNS record-type anomaly detection
- TLS metadata analysis
- JA4/JA4S extraction
- QUIC metadata analysis
- Standardized alerts
- End-to-end ML inference
- Throughput and latency measurement
- Live/replay dashboard integration

### Finalization only
- Final repository review and Git commit
- Final SIH presentation/demo packaging
