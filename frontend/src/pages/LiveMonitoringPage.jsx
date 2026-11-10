import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  Clock3,
  Database,
  Gauge,
  Globe2,
  LockKeyhole,
  Pause,
  Play,
  Radar,
  Radio,
  ShieldAlert,
  Target,
  Zap,
} from "lucide-react";
import { motion } from "framer-motion";

import {
  replayDns,
  replayTls,
  replayQuic,
} from "../services/api";

function LiveMonitoringPage({
  analytics,
  alerts,
  runReplay,
  replaying,
  onAlertsDetected,
}) {
  const [tick, setTick] = useState(0);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const [dnsReplaying, setDnsReplaying] = useState(false);
  const [tlsReplaying, setTlsReplaying] = useState(false);

  const [dnsStats, setDnsStats] = useState(null);
  const [dnsAlerts, setDnsAlerts] = useState([]);

  const [tlsStats, setTlsStats] = useState(null);
  const [tlsDetections, setTlsDetections] = useState([]);

  const [quicReplaying, setQuicReplaying] = useState(false);
  const [quicStats, setQuicStats] = useState(null);
  const [quicDetections, setQuicDetections] = useState([]);

  const [streamError, setStreamError] = useState("");

  useEffect(() => {
    const timer = setInterval(() => {
      setTick((value) => value + 1);
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const flowCount = analytics?.total_flows ?? 0;
  const threatCount = analytics?.threat_flows ?? 0;
  const speed = analytics?.processing?.flows_per_second ?? 0;

  const visibleAlerts = useMemo(
    () => (Array.isArray(alerts) ? alerts.slice(0, 8) : []),
    [alerts]
  );

  useEffect(() => {
    if (!selectedAlert && visibleAlerts.length > 0) {
      setSelectedAlert(visibleAlerts[0]);
    }
  }, [visibleAlerts, selectedAlert]);

  async function runDnsReplay() {
    if (dnsReplaying) return;

    try {
      setDnsReplaying(true);
      setStreamError("");

      const result = await replayDns(100);

      setDnsStats(result?.dns_statistics || null);
      const latestDnsAlerts =
        Array.isArray(result?.alerts) ? result.alerts : [];

      setDnsAlerts(latestDnsAlerts);

      if (typeof onAlertsDetected === "function") {
        onAlertsDetected(latestDnsAlerts);
      }
    } catch (err) {
      console.error("NETRA DNS replay error:", err);

      setStreamError(
        err?.response?.data?.detail ||
          err?.message ||
          "DNS replay failed"
      );
    } finally {
      setDnsReplaying(false);
    }
  }

  async function runTlsReplay() {
    if (tlsReplaying) return;

    try {
      setTlsReplaying(true);
      setStreamError("");

      const result = await replayTls(100);

      setTlsStats(result?.tls_statistics || null);
      const latestTlsDetections =
        Array.isArray(result?.detections)
          ? result.detections
          : [];

      setTlsDetections(latestTlsDetections);

      if (typeof onAlertsDetected === "function") {
        onAlertsDetected(latestTlsDetections);
      }
    } catch (err) {
      console.error("NETRA TLS replay error:", err);

      setStreamError(
        err?.response?.data?.detail ||
          err?.message ||
          "TLS replay failed"
      );
    } finally {
      setTlsReplaying(false);
    }
  }



  async function runQuicReplay() {
    if (quicReplaying) return;

    try {
      setQuicReplaying(true);
      setStreamError("");

      const result = await replayQuic(100);

      setQuicStats(result?.quic_statistics || null);
      const latestQuicDetections =
        Array.isArray(result?.detections)
          ? result.detections
          : [];

      setQuicDetections(latestQuicDetections);

      if (typeof onAlertsDetected === "function") {
        onAlertsDetected(latestQuicDetections);
      }
    } catch (err) {
      console.error("NETRA QUIC replay error:", err);

      setStreamError(
        err?.response?.data?.detail ||
          err?.message ||
          "QUIC replay failed"
      );
    } finally {
      setQuicReplaying(false);
    }
  }

  return (
    <div className="special-page">
      <PageHeader
        title="Live Monitoring"
        eyebrow="REPLAY TELEMETRY"
        description="Passive network observation and replay-based threat detection."
      />

      {streamError && (
        <div className="api-warning">
          <AlertTriangle size={17} />
          <span>{streamError}</span>
        </div>
      )}

      <section className="monitor-status">
        <div className="monitor-core">
          <div className="radar-sweep" />
          <div className="radar-ring ring-one" />
          <div className="radar-ring ring-two" />
          <div className="radar-ring ring-three" />

          <div className="radar-center">
            <Radar size={27} />
          </div>
        </div>

        <div className="monitor-status-copy">
          <span className="monitor-label">
            <span className="live-dot" />
            PASSIVE MONITORING
          </span>

          <h2>Network Telemetry Engine</h2>

          <p>
            NETRA observes flow, DNS, and encrypted TLS metadata without
            transmitting probes or decrypting payloads.
          </p>
        </div>

        <button
          className="primary-button monitor-button"
          onClick={runReplay}
          disabled={replaying}
        >
          {replaying ? (
            <>
              <Pause size={16} />
              REPLAYING CAPTURED FLOWS
            </>
          ) : (
            <>
              <Play size={16} />
              REPLAY CAPTURED FLOWS
            </>
          )}
        </button>
      </section>

      <section className="monitor-controls">
        <ReplayControl
          icon={Globe2}
          title="DNS REPLAY"
          description="Zeek DNS metadata and tunnel detection"
          buttonText={dnsReplaying ? "RUNNING..." : "RUN DNS REPLAY"}
          onClick={runDnsReplay}
          disabled={dnsReplaying}
        />

        <ReplayControl
          icon={LockKeyhole}
          title="TLS REPLAY"
          description="TLS metadata, JA4/JA4S and behavioral analysis"
          buttonText={tlsReplaying ? "RUNNING..." : "RUN TLS REPLAY"}
          onClick={runTlsReplay}
          disabled={tlsReplaying}
        />


        <ReplayControl
          icon={LockKeyhole}
          title="QUIC REPLAY"
          description="QUIC metadata and behavioral analysis"
          buttonText={quicReplaying ? "RUNNING..." : "RUN QUIC REPLAY"}
          onClick={runQuicReplay}
          disabled={quicReplaying}
        />
      </section>

      <section className="monitor-stats">
        <MonitorStat
          label="FLOWS PROCESSED"
          value={flowCount}
          icon={Activity}
        />

        <MonitorStat
          label="THREATS DETECTED"
          value={threatCount}
          icon={ShieldAlert}
          danger
        />

        <MonitorStat
          label="THROUGHPUT"
          value={`${Number(speed).toFixed(2)} / SEC`}
          icon={Zap}
        />

        <MonitorStat
          label="SESSION AGE"
          value={`${tick}s`}
          icon={Radio}
        />
      </section>

      <section className="monitor-grid">
        <div className="monitor-card monitor-chart-card">
          <div className="special-card-heading">
            <div>
              <span>STREAM PROCESSOR</span>
              <h3>Replay Traffic Activity</h3>
            </div>

            <div className={`live-chip ${replaying ? "active" : ""}`}>
              <span />
              {replaying ? "REPLAY ACTIVE" : "PASSIVE READY"}
            </div>
          </div>

          <TrafficWave active={replaying} />

          <div className="processor-meta">
            <div>
              <span>MODE</span>
              <strong>PASSIVE</strong>
            </div>

            <div>
              <span>INPUT</span>
              <strong>FLOW / DNS / TLS / QUIC</strong>
            </div>

            <div>
              <span>DECRYPTION</span>
              <strong>DISABLED</strong>
            </div>
          </div>
        </div>

        <div className="monitor-card">
          <div className="special-card-heading">
            <div>
              <span>DETECTION STREAM</span>
              <h3>Latest Events</h3>
            </div>

            <div className="event-count-chip">
              {visibleAlerts.length}
            </div>
          </div>

          <div className="event-stream">
            {visibleAlerts.map((alert, index) => (
              <motion.button
                type="button"
                className={`stream-event ${
                  selectedAlert?.alert_id === alert.alert_id
                    ? "selected"
                    : ""
                }`}
                key={alert.alert_id || index}
                initial={{ opacity: 0, x: 15 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.03 }}
                onClick={() => setSelectedAlert(alert)}
              >
                <span className="event-time">
                  {formatTime(alert.timestamp)}
                </span>

                <div
                  className={`event-indicator ${String(
                    alert.severity || "HIGH"
                  ).toLowerCase()}`}
                />

                <div className="event-copy">
                  <strong>{alert.threat_class || "UNKNOWN"}</strong>
                  <span>{threatCoverageLabel(alert.threat_class)}</span>
                  <small>
                    {alert.flow_id || "FLOW IDENTIFIED"}
                  </small>
                </div>

                <span className="event-confidence">
                  {formatNumber(alert.confidence)}%
                </span>

                <ChevronDown size={14} className="event-chevron" />
              </motion.button>
            ))}

            {!visibleAlerts.length && (
              <div className="event-empty">
                <AlertTriangle size={20} />
                <span>
                  Start a flow replay to generate detections.
                </span>
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="telemetry-grid">
        <DnsReplayCard
          stats={dnsStats}
          alerts={dnsAlerts}
          loading={dnsReplaying}
        />

        <TlsReplayCard
          stats={tlsStats}
          detections={tlsDetections}
          loading={tlsReplaying}
        />


        <QuicReplayCard
          stats={quicStats}
          detections={quicDetections}
          loading={quicReplaying}
        />
      </section>

      <section className="monitor-card alert-detail-card">
        <div className="special-card-heading">
          <div>
            <span>THREAT INTELLIGENCE</span>
            <h3>Selected Detection</h3>
          </div>

          {selectedAlert && (
            <SeverityBadge severity={selectedAlert.severity} />
          )}
        </div>

        {selectedAlert ? (
          <AlertDetails alert={selectedAlert} />
        ) : (
          <div className="event-empty detail-empty">
            <Target size={20} />
            <span>Select a detection from the event stream.</span>
          </div>
        )}
      </section>
    </div>
  );
}

function ReplayControl({
  icon: Icon,
  title,
  description,
  buttonText,
  onClick,
  disabled,
}) {
  return (
    <div className="replay-control">
      <div className="replay-control-icon">
        <Icon size={19} />
      </div>

      <div className="replay-control-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>

      <button
        type="button"
        className="secondary-button"
        onClick={onClick}
        disabled={disabled}
      >
        {buttonText}
      </button>
    </div>
  );
}

function DnsReplayCard({ stats, alerts, loading }) {
  return (
    <div className="monitor-card telemetry-card">
      <div className="special-card-heading">
        <div>
          <span>DNS TELEMETRY</span>
          <h3>DNS Replay</h3>
        </div>

        <div className="telemetry-icon dns">
          <Globe2 size={18} />
        </div>
      </div>

      {loading ? (
        <TelemetryLoading text="RUNNING DNS REPLAY" />
      ) : stats ? (
        <>
          <div className="telemetry-metrics">
            <TelemetryMetric
              label="RECORDS"
              value={stats.records_processed}
            />
            <TelemetryMetric
              label="THREATS"
              value={stats.threat_alerts}
            />
            <TelemetryMetric
              label="RECORDS / SEC"
              value={stats.records_per_second}
            />
          </div>

          <div className="telemetry-footer">
            <span>STATUS</span>
            <strong>
              {alerts.length ? `${alerts.length} ALERTS` : "NO THREATS"}
            </strong>
          </div>
        </>
      ) : (
        <TelemetryEmpty
          icon={Database}
          text="Run DNS replay to inspect DNS telemetry."
        />
      )}
    </div>
  );
}

function TlsReplayCard({ stats, detections, loading }) {
  const latest = detections.length
    ? detections[detections.length - 1]
    : null;

  const evidence = latest?.evidence || {};

  return (
    <div className="monitor-card telemetry-card">
      <div className="special-card-heading">
        <div>
          <span>ENCRYPTED METADATA</span>
          <h3>TLS Metadata</h3>
        </div>

        <div className="telemetry-icon tls">
          <LockKeyhole size={18} />
        </div>
      </div>

      {loading ? (
        <TelemetryLoading text="RUNNING TLS REPLAY" />
      ) : stats ? (
        <>
          <div className="telemetry-metrics">
            <TelemetryMetric
              label="TLS RECORDS"
              value={stats.records_processed}
            />

            <TelemetryMetric
              label="JA4"
              value={stats.unique_ja4?.length || 0}
            />

            <TelemetryMetric
              label="JA4S"
              value={stats.unique_ja4s?.length || 0}
            />

            <TelemetryMetric
              label="DECRYPTION"
              value={stats.payload_decryption ? "YES" : "NO"}
            />
          </div>

          {latest && (
            <div className="tls-summary">
              <div>
                <span>VERSION</span>
                <strong>{evidence.tls_version || "N/A"}</strong>
              </div>

              <div>
                <span>SNI</span>
                <strong>
                  {evidence.server_name || "NONE"}
                </strong>
              </div>

              <div>
                <span>JA4</span>
                <strong title={evidence.ja4 || ""}>
                  {evidence.ja4 || "NONE"}
                </strong>
              </div>

              <div>
                <span>JA4S</span>
                <strong title={evidence.ja4s || ""}>
                  {evidence.ja4s || "NONE"}
                </strong>
              </div>
            </div>
          )}

          <div className="telemetry-footer">
            <span>DECRYPTION STATUS</span>
            <strong>PAYLOAD DECRYPTION: NO</strong>
          </div>
        </>
      ) : (
        <TelemetryEmpty
          icon={LockKeyhole}
          text="Run TLS replay to inspect encrypted traffic metadata."
        />
      )}
    </div>
  );
}


function QuicReplayCard({ stats, detections, loading }) {
  const latest = detections.length
    ? detections[detections.length - 1]
    : null;

  const evidence = latest?.evidence || {};

  return (
    <div className="monitor-card telemetry-card">
      <div className="special-card-heading">
        <div>
          <span>ENCRYPTED METADATA</span>
          <h3>QUIC Metadata</h3>
        </div>

        <div className="telemetry-icon tls">
          <LockKeyhole size={18} />
        </div>
      </div>

      {loading ? (
        <TelemetryLoading text="RUNNING QUIC REPLAY" />
      ) : stats ? (
        <>
          <div className="telemetry-metrics">
            <TelemetryMetric
              label="QUIC RECORDS"
              value={stats.records_processed}
            />

            <TelemetryMetric
              label="THREATS"
              value={stats.threat_alerts}
            />

            <TelemetryMetric
              label="RECORDS / SEC"
              value={stats.records_per_second}
            />

            <TelemetryMetric
              label="DECRYPTION"
              value={stats.payload_decryption ? "YES" : "NO"}
            />
          </div>

          {latest && (
            <div className="tls-summary">
              <div>
                <span>VERSION</span>
                <strong>
                  {evidence.quic_version || "N/A"}
                </strong>
              </div>

              <div>
                <span>PROTOCOL</span>
                <strong>
                  {evidence.client_protocol || "N/A"}
                </strong>
              </div>

              <div>
                <span>SERVER NAME</span>
                <strong>
                  {evidence.server_name || "NONE"}
                </strong>
              </div>

              <div>
                <span>SIGNALS</span>
                <strong>
                  {evidence.supporting_signal_count ?? 0}
                </strong>
              </div>
            </div>
          )}
        </>
      ) : (
        <TelemetryEmpty
          icon={LockKeyhole}
          text="Run QUIC replay to inspect encrypted traffic metadata."
        />
      )}
    </div>
  );
}


function TelemetryMetric({ label, value }) {
  return (
    <div className="telemetry-metric">
      <span>{label}</span>
      <strong>{formatEvidenceValue(value)}</strong>
    </div>
  );
}

function TelemetryLoading({ text }) {
  return (
    <div className="telemetry-loading">
      <div className="data-loading-ring" />
      <strong>{text}</strong>
    </div>
  );
}

function TelemetryEmpty({ icon: Icon, text }) {
  return (
    <div className="telemetry-empty">
      <Icon size={24} />
      <span>{text}</span>
    </div>
  );
}

function PageHeader({ title, eyebrow, description }) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          {eyebrow}
        </div>

        <h1>{title}</h1>

        <p>{description}</p>
      </div>
    </div>
  );
}

function MonitorStat({
  label,
  value,
  icon: Icon,
  danger,
}) {
  return (
    <motion.div
      className={`monitor-stat ${danger ? "danger" : ""}`}
      whileHover={{ y: -4 }}
    >
      <div className="monitor-stat-icon">
        <Icon size={19} />
      </div>

      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </motion.div>
  );
}

function SeverityBadge({ severity }) {
  const value = String(severity || "UNKNOWN").toUpperCase();

  return (
    <span
      className={`severity-badge ${value.toLowerCase()}`}
    >
      {value}
    </span>
  );
}

function AlertDetails({ alert }) {
  const evidence = getAlertEvidence(alert);
  const evidenceEntries = Object.entries(evidence);

  return (
    <div className="alert-detail-layout">
      <div className="alert-primary">
        <div className="alert-title-row">
          <div>
            <span className="detail-label">THREAT CLASS</span>
            <h2>{alert?.threat_class || "UNKNOWN"}</h2>

            <div className="threat-category-badge">
              {threatCoverageLabel(alert?.threat_class)}
            </div>
          </div>

          <div className="confidence-display">
            <Gauge size={18} />
            <div>
              <span>CONFIDENCE</span>
              <strong>
                {formatNumber(alert?.confidence)}%
              </strong>
            </div>
          </div>
        </div>

        <div className="detail-grid">
          <DetailItem
            icon={Clock3}
            label="TIMESTAMP"
            value={formatTimestamp(alert?.timestamp)}
          />

          <DetailItem
            icon={Target}
            label="FLOW ID"
            value={alert?.flow_id || "N/A"}
          />

          <DetailItem
            icon={ShieldAlert}
            label="SEVERITY"
            value={String(
              alert?.severity || "UNKNOWN"
            ).toUpperCase()}
          />

          <DetailItem
            icon={Radar}
            label="ALERT ID"
            value={alert?.alert_id || "N/A"}
          />
        </div>
      </div>

      <div className="evidence-panel">
        <div className="evidence-heading">
          <span>SUPPORTING EVIDENCE</span>
          <strong>
            {evidenceEntries.length} INDICATORS
          </strong>
        </div>

        <div className="evidence-grid">
          {evidenceEntries.map(([key, value]) => (
            <div className="evidence-item" key={key}>
              <span>{evidenceLabel(key)}</span>
              <strong>{formatEvidenceValue(value)}</strong>
            </div>
          ))}

          {!evidenceEntries.length && (
            <div className="evidence-empty">
              <strong>NO DETECTOR EVIDENCE AVAILABLE</strong>
              <span>
                Standard alert metadata is available for this detection.
              </span>
              <div className="evidence-fallback">
                <div className="evidence-item">
                  <span>FLOW ID</span>
                  <strong>
                    {alert?.flow_id || "N/A"}
                  </strong>
                </div>

                <div className="evidence-item">
                  <span>THREAT</span>
                  <strong>
                    {alert?.threat_class || "UNKNOWN"}
                  </strong>
                </div>

                <div className="evidence-item">
                  <span>CONFIDENCE</span>
                  <strong>
                    {formatNumber(alert?.confidence)}%
                  </strong>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function getAlertEvidence(alert) {
  if (!alert || typeof alert !== "object") {
    return {};
  }

  const candidates = [
    alert.supporting_evidence,
    alert.evidence,
    alert.supportingEvidence,
    alert.detection_evidence,
    alert.detectionEvidence,
  ];

  for (const candidate of candidates) {
    if (
      candidate &&
      typeof candidate === "object" &&
      !Array.isArray(candidate) &&
      Object.keys(candidate).length > 0
    ) {
      return candidate;
    }
  }

  // Some API responses can wrap the alert payload.
  const nestedCandidates = [
    alert.data?.supporting_evidence,
    alert.data?.evidence,
    alert.result?.supporting_evidence,
    alert.result?.evidence,
    alert.detection?.supporting_evidence,
    alert.detection?.evidence,
  ];

  for (const candidate of nestedCandidates) {
    if (
      candidate &&
      typeof candidate === "object" &&
      !Array.isArray(candidate) &&
      Object.keys(candidate).length > 0
    ) {
      return candidate;
    }
  }

  return {};
}

function evidenceLabel(key) {
  const labels = {
    source_ip: "SOURCE IP",
    destination_ip: "DESTINATION IP",
    destination: "DESTINATION",
    flow_id: "FLOW ID",
    timestamp: "TIMESTAMP",
    protocol: "PROTOCOL",
    window_seconds: "WINDOW",
    source_flow_count: "FLOW COUNT",
    source_flow_rate: "FLOW RATE",
    destination_source_entropy: "SOURCE ENTROPY",
    syn_like_pattern: "SYN-LIKE PATTERN",
    unique_destination_ports: "DESTINATION PORTS",
    unique_destination_hosts: "DESTINATION HOSTS",
    outbound_bytes: "OUTBOUND BYTES",
    inbound_bytes: "INBOUND BYTES",
    outbound_inbound_ratio: "OUTBOUND / INBOUND RATIO",
    event_count: "EVENT COUNT",
    periodicity_cv: "PERIODICITY CV",
    query: "QUERY",
    query_count: "QUERY COUNT",
    query_length: "QUERY LENGTH",
    longest_label_length: "LONGEST LABEL",
    entropy: "ENTROPY",
    max_label_entropy: "MAX LABEL ENTROPY",
    digit_ratio: "DIGIT RATIO",
    dominant_record_type: "DOMINANT RECORD TYPE",
    dominant_ratio: "DOMINANT RATIO",
    record_type_diversity: "RECORD TYPE DIVERSITY",
    tls_version: "TLS VERSION",
    cipher: "CIPHER",
    server_name: "SERVER NAME",
    ja3: "JA3",
    ja3s: "JA3S",
    ja4: "JA4",
    ja4s: "JA4S",
    quic_version: "QUIC VERSION",
    client_protocol: "APPLICATION PROTOCOL",
    supporting_signal_count: "SUPPORTING SIGNALS",
    payload_decryption: "PAYLOAD DECRYPTION",
  };

  return (
    labels[key] ||
    String(key || "")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase())
  );
}


function DetailItem({ icon: Icon, label, value }) {
  return (
    <div className="detail-item">
      <Icon size={16} />

      <div>
        <span>{label}</span>
        <strong title={value}>{value}</strong>
      </div>
    </div>
  );
}

function TrafficWave({ active }) {
  const bars = [
    28, 43, 35, 63, 50, 78, 59, 84, 45,
    68, 56, 91, 71, 48, 73, 60, 85, 53,
    67, 42, 77, 61, 89, 55, 70, 46,
  ];

  return (
    <div className={`traffic-wave ${active ? "active" : ""}`}>
      {bars.map((height, index) => (
        <motion.div
          key={index}
          style={{ height: `${height}%` }}
          animate={
            active
              ? {
                  scaleY: [0.72, 1.08, 0.78],
                }
              : {}
          }
          transition={{
            duration: 1.2,
            repeat: Infinity,
            delay: index * 0.035,
          }}
        />
      ))}
    </div>
  );
}

function formatTime(timestamp) {
  if (!timestamp) return "--:--:--";

  try {
    return new Date(timestamp).toLocaleTimeString([], {
      hour12: false,
    });
  } catch {
    return "--:--:--";
  }
}

function formatTimestamp(timestamp) {
  if (!timestamp) return "N/A";

  try {
    return new Date(timestamp).toLocaleString([], {
      hour12: false,
    });
  } catch {
    return "N/A";
  }
}

function formatNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "0";
  }

  return Number.isInteger(number)
    ? String(number)
    : number.toFixed(2);
}

function formatKey(key) {
  return String(key)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}


function threatCoverageLabel(threatClass) {
  const threat = String(threatClass || "").toUpperCase();

  const labels = {
    DDOS: "VOLUMETRIC / PROTOCOL DDoS",
    PORTSCAN: "RECONNAISSANCE",
    BOT_C2: "BOTNET C2 BEACONING",
    DGA: "DGA / DNS ANOMALY",
    DNS_TUNNEL: "DNS TUNNELLING",
    DNS_RECORD_ANOMALY: "DNS RECORD-TYPE ANOMALY",
    EXFILTRATION: "DATA EXFILTRATION",
    DOS: "DENIAL OF SERVICE",
    BRUTE_FORCE: "BRUTE FORCE",
    WEB_ATTACK: "WEB ATTACK",
  };

  return labels[threat] || "NETWORK THREAT DETECTION";
}

function formatEvidenceValue(value) {
  if (value === null || value === undefined) {
    return "N/A";
  }

  if (typeof value === "boolean") {
    return value ? "YES" : "NO";
  }

  if (typeof value === "number") {
    return Number.isInteger(value)
      ? String(value)
      : value.toFixed(3);
  }

  return String(value);
}

export default LiveMonitoringPage;
