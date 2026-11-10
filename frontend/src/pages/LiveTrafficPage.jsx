import { useEffect, useMemo, useState } from "react";

import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Clock3,
  Eye,
  Globe2,
  Network,
  Radio,
  RefreshCw,
  ShieldAlert,
  Signal,
  Wifi,
  Zap,
} from "lucide-react";

import { motion } from "framer-motion";

import {
  getLiveEvents,
  getLiveAlerts,
  getLiveStatus,
  pollLiveNetwork,
} from "../services/api";


function LiveTrafficPage() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] =
    useState(null);


  const loadLiveTraffic = async (
    manual = false
  ) => {
    try {
      if (manual) {
        setRefreshing(true);
      }

      setError("");

      await pollLiveNetwork(100);

      const [
        eventsResult,
        alertsResult,
        statusResult,
      ] = await Promise.all([
        getLiveEvents(),
        getLiveAlerts(),
        getLiveStatus(),
      ]);

      const latestEvents =
        Array.isArray(
          eventsResult?.events
        )
          ? eventsResult.events
          : [];

      const latestAlerts =
        Array.isArray(
          alertsResult?.alerts
        )
          ? alertsResult.alerts
          : [];

      setEvents(
        latestEvents
      );

      setAlerts(
        latestAlerts
      );

      setStatus(
        statusResult || null
      );

      setLastUpdated(
        new Date()
      );

    } catch (err) {
      console.error(
        "NETRA live traffic error:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Unable to connect to the live telemetry engine"
      );

    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };


  useEffect(() => {
    loadLiveTraffic();

    const interval =
      setInterval(() => {
        loadLiveTraffic();
      }, 3000);

    return () =>
      clearInterval(interval);

  }, []);


  const flowEvents =
    useMemo(() => {
      return events.filter(
        (event) =>
          event?.event_type === "flow" ||
          event?.flow_id
      );
    }, [events]);


  const threatFlows =
    useMemo(() => {
      return flowEvents.filter(
        (event) =>
          Array.isArray(
            event?.alerts
          ) &&
          event.alerts.length > 0
      );
    }, [flowEvents]);


  const protocolStats =
    useMemo(() => {
      const stats = {};

      flowEvents.forEach(
        (flow) => {
          const protocol =
            String(
              flow?.protocol ||
                "UNKNOWN"
            ).toUpperCase();

          stats[protocol] =
            (
              stats[protocol] ||
              0
            ) + 1;
        }
      );

      return Object.entries(
        stats
      ).sort(
        (a, b) =>
          b[1] - a[1]
      );

    }, [flowEvents]);


  const trafficTotals =
    useMemo(() => {
      let originatingBytes = 0;
      let respondingBytes = 0;
      let packets = 0;

      flowEvents.forEach(
        (flow) => {
          originatingBytes +=
            Number(
              flow?.orig_bytes ||
                0
            );

          respondingBytes +=
            Number(
              flow?.resp_bytes ||
                0
            );

          packets +=
            Number(
              flow?.orig_packets ||
                0
            ) +
            Number(
              flow?.resp_packets ||
                0
            );
        }
      );

      return {
        originatingBytes,
        respondingBytes,
        packets,
      };

    }, [flowEvents]);


  const latestThreat =
    alerts.length > 0
      ? alerts[0]
      : null;


  return (
    <div className="special-page telemetry-command-page">

      <div className="telemetry-command-header">

        <div>

          <div className="eyebrow">
            <span className="eyebrow-line" />
            ADVANCED NETWORK TELEMETRY
          </div>

          <h1>
            Traffic Command Center
          </h1>

          <p>
            Real-time passive flow intelligence,
            behavioral analysis and threat correlation
            from the NETRA monitoring pipeline.
          </p>

        </div>


        <div className="command-header-actions">

          <div className="telemetry-last-update">

            <Clock3 size={14} />

            <div>
              <span>
                LAST TELEMETRY UPDATE
              </span>

              <strong>
                {lastUpdated
                  ? lastUpdated.toLocaleTimeString()
                  : "CONNECTING"}
              </strong>
            </div>

          </div>


          <button
            type="button"
            className="secondary-button"
            onClick={() =>
              loadLiveTraffic(true)
            }
            disabled={refreshing}
          >

            <RefreshCw
              size={16}
              className={
                refreshing
                  ? "refresh-spinning"
                  : ""
              }
            />

            {refreshing
              ? "SYNCING..."
              : "SYNC NOW"}

          </button>

        </div>

      </div>


      {error && (

        <div className="api-warning">

          <AlertTriangle size={17} />

          <span>
            {error}
          </span>

        </div>

      )}


      {/* COMMAND STATUS BAR */}

      <section className="telemetry-status-bar">

        <StatusSignal
          icon={Signal}
          label="TELEMETRY STREAM"
          value={
            loading
              ? "CONNECTING"
              : error
                ? "INTERRUPTED"
                : "ACTIVE"
          }
          active={
            !loading &&
            !error
          }
        />


        <StatusSignal
          icon={Eye}
          label="MONITORING MODE"
          value="PASSIVE"
          active
        />


        <StatusSignal
          icon={Network}
          label="FLOWS PROCESSED"
          value={
            status?.processed_flows ??
            flowEvents.length
          }
          active
        />


        <StatusSignal
          icon={ShieldAlert}
          label="THREAT SIGNALS"
          value={alerts.length}
          danger={
            alerts.length > 0
          }
        />


        <StatusSignal
          icon={Wifi}
          label="ZEEK SENSOR"
          value={
            status?.zeek_log_exists
              ? "CONNECTED"
              : "WAITING"
          }
          active={
            status?.zeek_log_exists
          }
        />

      </section>


      {/* TOP COMMAND CARDS */}

      <section className="telemetry-overview-grid">

        <div className="monitor-card telemetry-hero-card">

          <div className="telemetry-hero-top">

            <div>

              <span className="telemetry-section-label">
                LIVE SENSOR FEED
              </span>

              <h2>
                Network Telemetry Pipeline
              </h2>

            </div>


            <div className="live-chip active">

              <span />

              LIVE

            </div>

          </div>


          <div className="telemetry-pipeline">

            <PipelineNode
              label="NETWORK"
              value="OBSERVED"
              icon={Network}
            />

            <div className="pipeline-line">
              <span />
            </div>

            <PipelineNode
              label="ZEEK"
              value="CAPTURE"
              icon={Radio}
            />

            <div className="pipeline-line">
              <span />
            </div>

            <PipelineNode
              label="NETRA AI"
              value="ANALYZE"
              icon={Activity}
            />

            <div className="pipeline-line">
              <span />
            </div>

            <PipelineNode
              label="THREAT"
              value={
                alerts.length > 0
                  ? "DETECTED"
                  : "CLEAR"
              }
              icon={ShieldAlert}
              danger={
                alerts.length > 0
              }
            />

          </div>


          <div className="telemetry-hero-footer">

            <span>
              Passive observation enabled.
              No active probes are injected
              into the monitored network.
            </span>

            <strong>
              POLLING EVERY 3 SECONDS
            </strong>

          </div>

        </div>


        <div
          className={`monitor-card threat-command-card ${
            alerts.length > 0
              ? "has-threat"
              : ""
          }`}
        >

          <div className="threat-command-heading">

            <div>

              <span>
                CURRENT SECURITY POSTURE
              </span>

              <h3>
                Threat Intelligence
              </h3>

            </div>

            <ShieldAlert size={20} />

          </div>


          {latestThreat ? (

            <div className="latest-threat">

              <div className="latest-threat-main">

                <span className="threat-live-dot" />

                <div>

                  <small>
                    LATEST DETECTION
                  </small>

                  <strong>
                    {latestThreat.threat_class ||
                      "UNKNOWN THREAT"}
                  </strong>

                </div>

              </div>


              <div className="threat-confidence-box">

                <span>
                  CONFIDENCE
                </span>

                <strong>
                  {formatConfidence(
                    latestThreat.confidence
                  )}%
                </strong>

              </div>


              <div className="latest-threat-evidence">

                <span>
                  DESTINATION
                </span>

                <strong>
                  {
                    latestThreat
                      ?.supporting_evidence
                      ?.destination ||
                    "NETWORK FLOW"
                  }
                </strong>

              </div>

            </div>

          ) : (

            <div className="threat-clear-state">

              <ShieldAlert size={28} />

              <div>

                <strong>
                  No Active Threat Signal
                </strong>

                <span>
                  Behavioral detection engine
                  has not generated a new alert.
                </span>

              </div>

            </div>

          )}

        </div>

      </section>


      {/* STATISTICS */}

      <section className="telemetry-metrics-grid">

        <TelemetryMetric
          label="ACTIVE FLOW CACHE"
          value={flowEvents.length}
          sublabel="NETWORK CONNECTIONS"
          icon={Network}
        />

        <TelemetryMetric
          label="BEHAVIORAL THREATS"
          value={threatFlows.length}
          sublabel="ANOMALOUS FLOWS"
          icon={ShieldAlert}
          danger={
            threatFlows.length > 0
          }
        />

        <TelemetryMetric
          label="ORIGINATING DATA"
          value={
            formatBytes(
              trafficTotals.originatingBytes
            )
          }
          sublabel="SOURCE → NETWORK"
          icon={ArrowUpRight}
        />

        <TelemetryMetric
          label="TOTAL PACKETS"
          value={
            trafficTotals.packets
          }
          sublabel="OBSERVED TELEMETRY"
          icon={Zap}
        />

      </section>


      {/* MAIN WORKSPACE */}

      <section className="telemetry-workspace-grid">


        {/* FLOW TABLE */}

        <div className="monitor-card telemetry-flow-workspace">

          <div className="workspace-heading">

            <div>

              <span>
                REAL-TIME FLOW MATRIX
              </span>

              <h3>
                Network Connections
              </h3>

            </div>


            <div className="workspace-meta">

              <span>
                {flowEvents.length}
                {" "}
                FLOWS
              </span>

              <span className="workspace-live-dot" />

              <strong>
                STREAMING
              </strong>

            </div>

          </div>


          <div className="live-flow-table">

            <div className="live-flow-header">

              <span>
                TIME
              </span>

              <span>
                SOURCE
              </span>

              <span>
                DESTINATION
              </span>

              <span>
                PROTOCOL
              </span>

              <span>
                STATE
              </span>

              <span>
                RISK
              </span>

            </div>


            {flowEvents
              .slice(0, 12)
              .map(
                (
                  flow,
                  index
                ) => {

                  const hasAlert =
                    Array.isArray(
                      flow.alerts
                    ) &&
                    flow.alerts.length > 0;

                  return (

                    <motion.div
                      className={`live-flow-row ${
                        hasAlert
                          ? "flow-row-threat"
                          : ""
                      }`}
                      key={
                        flow.flow_id ||
                        index
                      }
                      initial={{
                        opacity: 0,
                        y: 8,
                      }}
                      animate={{
                        opacity: 1,
                        y: 0,
                      }}
                    >

                      <span>
                        {formatTime(
                          flow.timestamp
                        )}
                      </span>


                      <strong>
                        {formatEndpoint(
                          flow.source_ip,
                          flow.source_port
                        )}
                      </strong>


                      <strong>
                        {formatEndpoint(
                          flow.destination_ip,
                          flow.destination_port
                        )}
                      </strong>


                      <span className="protocol-chip">
                        {String(
                          flow.protocol ||
                            "UNKNOWN"
                        ).toUpperCase()}
                      </span>


                      <span className="flow-state">
                        {flow.conn_state ||
                          "N/A"}
                      </span>


                      <span
                        className={`flow-status ${
                          hasAlert
                            ? "threat"
                            : "normal"
                        }`}
                      >

                        {hasAlert
                          ? "THREAT"
                          : "NORMAL"}

                      </span>

                    </motion.div>

                  );

                }
              )}


            {!loading &&
              flowEvents.length === 0 && (

                <div className="telemetry-empty-state">

                  <Network size={26} />

                  <strong>
                    Waiting for live flows
                  </strong>

                  <span>
                    The NETRA telemetry engine
                    is ready to receive network
                    connection records.
                  </span>

                </div>

              )}

          </div>

        </div>


        {/* ALERT WORKSPACE */}

        <div className="monitor-card telemetry-alert-workspace">

          <div className="workspace-heading">

            <div>

              <span>
                SECURITY EVENT QUEUE
              </span>

              <h3>
                Threat Detections
              </h3>

            </div>


            <div className="event-count-chip">

              {alerts.length}

            </div>

          </div>


          <div className="threat-event-list">

            {alerts
              .slice(0, 3)
              .map(
                (
                  alert,
                  index
                ) => (

                  <motion.div
                    className="threat-event-card"
                    key={
                      alert.alert_id ||
                      index
                    }
                    initial={{
                      opacity: 0,
                      x: 15,
                    }}
                    animate={{
                      opacity: 1,
                      x: 0,
                    }}
                  >

                    <div className="threat-event-top">

                      <div className="threat-event-title">

                        <span
                          className={`event-indicator ${String(
                            alert.severity ||
                              "HIGH"
                          ).toLowerCase()}`}
                        />

                        <strong>
                          {alert.threat_class ||
                            "UNKNOWN"}
                        </strong>

                      </div>


                      <span className="threat-event-confidence">

                        {formatConfidence(
                          alert.confidence
                        )}%

                      </span>

                    </div>




                    <div className="threat-event-footer">

                      <span>
                        {formatTime(
                          alert.timestamp
                        )}
                      </span>

                      <span>
                        {String(
                          alert.severity ||
                            "HIGH"
                        ).toUpperCase()}
                      </span>

                    </div>

                  </motion.div>

                )
              )}


            {!loading &&
              alerts.length === 0 && (

                <div className="telemetry-clear-alert-state">

                  <ShieldAlert size={28} />

                  <strong>
                    Security Queue Clear
                  </strong>

                  <span>
                    No behavioral threat detections
                    are currently stored in the
                    live alert queue.
                  </span>

                </div>

              )}

          </div>

        </div>

      </section>


      {/* ANALYTICS */}

      <section className="telemetry-analytics-grid">


        <div className="monitor-card telemetry-protocol-card">

          <div className="workspace-heading">

            <div>

              <span>
                TRAFFIC COMPOSITION
              </span>

              <h3>
                Protocol Distribution
              </h3>

            </div>

            <Globe2 size={19} />

          </div>


          <div className="protocol-distribution">

            {protocolStats.map(
              (
                [
                  protocol,
                  count,
                ]
              ) => (

                <div
                  className="protocol-row"
                  key={protocol}
                >

                  <div>

                    <span>
                      {protocol}
                    </span>

                    <strong>
                      {count} FLOWS
                    </strong>

                  </div>


                  <div className="protocol-bar">

                    <span
                      style={{
                        width: `${
                          flowEvents.length
                            ? (
                                count /
                                flowEvents.length
                              ) * 100
                            : 0
                        }%`,
                      }}
                    />

                  </div>

                </div>

              )
            )}


            {!protocolStats.length && (

              <div className="event-empty">

                <Globe2 size={20} />

                <span>
                  Waiting for protocol telemetry.
                </span>

              </div>

            )}

          </div>

        </div>


        <div className="monitor-card telemetry-characteristics-card">

          <div className="workspace-heading">

            <div>

              <span>
                FLOW CHARACTERISTICS
              </span>

              <h3>
                Traffic Direction
              </h3>

            </div>

            <Activity size={19} />

          </div>


          <div className="telemetry-characteristics-list">

            <TrafficCharacteristic
              icon={ArrowUpRight}
              label="ORIGINATING BYTES"
              value={
                formatBytes(
                  trafficTotals.originatingBytes
                )
              }
            />

            <TrafficCharacteristic
              icon={ArrowDownRight}
              label="RESPONDING BYTES"
              value={
                formatBytes(
                  trafficTotals.respondingBytes
                )
              }
            />

            <TrafficCharacteristic
              icon={Eye}
              label="OBSERVATION MODE"
              value="PASSIVE"
            />

            <TrafficCharacteristic
              icon={Wifi}
              label="SENSOR STATUS"
              value={
                status?.zeek_log_exists
                  ? "CONNECTED"
                  : "WAITING"
              }
            />

          </div>

        </div>


        <div className="monitor-card telemetry-engine-card">

          <div className="workspace-heading">

            <div>

              <span>
                AI ANALYSIS ENGINE
              </span>

              <h3>
                Behavioral Detection
              </h3>

            </div>

            <Zap size={19} />

          </div>


          <div className="engine-analysis-content">

            <div className="engine-status-orbit">

              <div className="engine-orbit-ring" />

              <div className="engine-orbit-core">

                <Activity size={25} />

              </div>

            </div>


            <div className="engine-analysis-copy">

              <strong>
                NETRA AI ENGINE ACTIVE
              </strong>

              <span>
                Flow telemetry is continuously
                evaluated for behavioral anomalies
                and periodic communication patterns.
              </span>

              <div className="engine-analysis-meta">

                <span>
                  <i />
                  PASSIVE ANALYSIS
                </span>

                <span>
                  <i />
                  REAL-TIME CORRELATION
                </span>

              </div>

            </div>

          </div>

        </div>

      </section>


    </div>
  );
}


function StatusSignal({
  icon: Icon,
  label,
  value,
  active,
  danger,
}) {

  return (

    <div className="status-signal">

      <div
        className={`status-signal-icon ${
          danger
            ? "danger"
            : active
              ? "active"
              : ""
        }`}
      >

        <Icon size={16} />

      </div>


      <div>

        <span>
          {label}
        </span>

        <strong
          className={
            danger
              ? "danger"
              : active
                ? "active"
                : ""
          }
        >

          {value}

        </strong>

      </div>

    </div>

  );
}


function PipelineNode({
  icon: Icon,
  label,
  value,
  danger,
}) {

  return (

    <div className="pipeline-node">

      <div
        className={`pipeline-node-icon ${
          danger
            ? "danger"
            : ""
        }`}
      >

        <Icon size={18} />

      </div>

      <span>
        {label}
      </span>

      <strong
        className={
          danger
            ? "danger"
            : ""
        }
      >

        {value}

      </strong>

    </div>

  );
}


function TelemetryMetric({
  label,
  value,
  sublabel,
  icon: Icon,
  danger,
}) {

  return (

    <div
      className={`monitor-card telemetry-metric-card ${
        danger
          ? "metric-danger"
          : ""
      }`}
    >

      <div className="telemetry-metric-icon">

        <Icon size={18} />

      </div>


      <div className="telemetry-metric-copy">

        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>

        <small>
          {sublabel}
        </small>

      </div>

    </div>

  );
}


function TrafficCharacteristic({
  icon: Icon,
  label,
  value,
}) {

  return (

    <div className="traffic-characteristic-item">

      <div>

        <Icon size={17} />

      </div>


      <span>
        {label}
      </span>


      <strong>
        {value}
      </strong>

    </div>

  );
}


function formatEndpoint(
  ip,
  port
) {

  if (!ip) {
    return "UNKNOWN";
  }

  return port
    ? `${ip}:${port}`
    : ip;
}


function formatTime(
  timestamp
) {

  if (
    timestamp === undefined ||
    timestamp === null ||
    timestamp === ""
  ) {
    return "--:--:--";
  }

  const numeric =
    Number(timestamp);

  if (
    Number.isNaN(numeric)
  ) {
    return "--:--:--";
  }

  const date =
    new Date(
      numeric * 1000
    );

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "--:--:--";
  }

  return date
    .toLocaleTimeString(
      [],
      {
        hour12: false,
      }
    );
}


function formatConfidence(
  confidence
) {

  const value =
    Number(confidence);

  if (
    Number.isNaN(value)
  ) {
    return "0.0";
  }

  return value.toFixed(1);
}


function formatBytes(
  bytes
) {

  const value =
    Number(bytes) || 0;

  if (
    value < 1024
  ) {
    return `${value} B`;
  }

  if (
    value < 1024 * 1024
  ) {
    return `${(
      value / 1024
    ).toFixed(2)} KB`;
  }

  return `${(
    value /
    (
      1024 *
      1024
    )
  ).toFixed(2)} MB`;
}


function formatEvidence(
  evidence
) {

  if (
    !evidence ||
    typeof evidence !==
      "object"
  ) {
    return "Behavioral detection";
  }


  if (
    evidence.destination
  ) {
    return `Destination: ${evidence.destination}`;
  }


  if (
    evidence.source_ip
  ) {
    return `Source: ${evidence.source_ip}`;
  }


  if (
    evidence.event_count
  ) {
    return `${evidence.event_count} correlated events`;
  }


  return "Behavioral detection";

}


export default LiveTrafficPage;
