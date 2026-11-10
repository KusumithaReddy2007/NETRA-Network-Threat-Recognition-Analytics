import {
  ArrowDownUp,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  Network,
  Search,
  Activity,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";

function FlowsPage({ analytics, flowResults = [] }) {
  const [query, setQuery] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [sortDirection, setSortDirection] = useState("desc");
  const [page, setPage] = useState(1);
  const [selectedFlow, setSelectedFlow] = useState(null);

  const pageSize = 25;

  const allFlows = Array.isArray(flowResults)
    ? flowResults
    : [];

  const threatOptions = useMemo(() => {
    return [
      "ALL",
      ...Array.from(
        new Set(
          allFlows
            .map((flow) => flow?.predicted_class)
            .filter(Boolean),
        ),
      ),
    ];
  }, [allFlows]);

  const severityOptions = useMemo(() => {
    return [
      "ALL",
      ...Array.from(
        new Set(
          allFlows
            .map((flow) => flow?.severity || "BENIGN")
            .filter(Boolean),
        ),
      ),
    ];
  }, [allFlows]);

  const filteredFlows = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    const result = allFlows.filter((flow) => {
      const searchable = Object.entries(flow || {})
        .map(([key, value]) => {
          if (typeof value === "boolean") {
            return `${key} ${value ? "yes" : "no"}`;
          }

          return `${key} ${value ?? ""}`;
        })
        .join(" ")
        .toLowerCase();

      const matchesQuery =
        !normalizedQuery ||
        searchable.includes(normalizedQuery);

      const matchesThreat =
        threatFilter === "ALL" ||
        flow?.predicted_class === threatFilter;

      const matchesSeverity =
        severityFilter === "ALL" ||
        (flow?.severity || "BENIGN") === severityFilter;

      return (
        matchesQuery &&
        matchesThreat &&
        matchesSeverity
      );
    });

    return [...result].sort((a, b) => {
      const aNumber = Number(a?.flow_number || 0);
      const bNumber = Number(b?.flow_number || 0);

      return sortDirection === "desc"
        ? bNumber - aNumber
        : aNumber - bNumber;
    });
  }, [
    allFlows,
    query,
    threatFilter,
    severityFilter,
    sortDirection,
  ]);

  const totalPages = Math.max(
    Math.ceil(filteredFlows.length / pageSize),
    1,
  );

  const safePage = Math.min(page, totalPages);

  const paginatedFlows = filteredFlows.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );

  const protocolUnavailable =
    "Current replay result schema exposes classifier output, not protocol metadata.";

  const classDistribution = useMemo(() => {
    const counts = {};

    allFlows.forEach((flow) => {
      const key = flow?.predicted_class || "UNKNOWN";
      counts[key] = (counts[key] || 0) + 1;
    });

    return Object.entries(counts).sort(
      (a, b) => b[1] - a[1],
    );
  }, [allFlows]);

  const setPageSafe = (nextPage) => {
    setPage(Math.max(1, Math.min(nextPage, totalPages)));
  };

  const resetFilters = () => {
    setQuery("");
    setSearchInput("");
    setThreatFilter("ALL");
    setSeverityFilter("ALL");
    setPage(1);
  };

  const exportJSON = () => {
    const blob = new Blob(
      [JSON.stringify(filteredFlows, null, 2)],
      { type: "application/json" },
    );

    downloadBlob(
      blob,
      `netra-flows-${new Date().toISOString()}.json`,
    );
  };

  const exportCSV = () => {
    const headers = [
      "flow_number",
      "expected_class",
      "predicted_class",
      "confidence",
      "alert_generated",
      "severity",
      "processing_time_ms",
    ];

    const rows = filteredFlows.map((flow) =>
      headers.map((key) => csvCell(flow?.[key])),
    );

    const csv = [
      headers.join(","),
      ...rows.map((row) => row.join(",")),
    ].join("\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;",
    });

    downloadBlob(
      blob,
      `netra-flows-${new Date().toISOString()}.csv`,
    );
  };

  return (
    <div className="special-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            NETWORK TELEMETRY
          </div>

          <h1>Flow Explorer</h1>

          <p>
            Flow-level metadata and model decisions produced
            by the NETRA replay detection engine.
          </p>
        </div>
      </div>

      <div className="flow-toolbar">
        <div className="flow-search">
          <Search size={17} />

          <input
            value={searchInput}
            onChange={(event) =>
              setSearchInput(event.target.value)
            }
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                setQuery(searchInput);
                setPage(1);
              }

              if (event.key === "Escape") {
                setSearchInput("");
                setQuery("");
                setPage(1);
              }
            }}
            placeholder="Search flow, class, confidence, severity..."
            aria-label="Search flows"
          />

          <button
            type="button"
            className="flow-search-button"
            onClick={() => {
              setQuery(searchInput);
              setPage(1);
            }}
          >
            SEARCH
          </button>
        </div>

        <button
          className="secondary-button"
          onClick={() =>
            setSortDirection((value) =>
              value === "desc" ? "asc" : "desc",
            )
          }
        >
          <ArrowDownUp size={15} />
          SORT {sortDirection === "desc" ? "NEWEST" : "OLDEST"}
        </button>
      </div>

      <div className="flow-summary">
        <FlowMetric
          icon={Network}
          label="OBSERVED FLOWS"
          value={analytics?.total_flows ?? allFlows.length}
        />

        <FlowMetric
          icon={Activity}
          label="THREAT FLOWS"
          value={analytics?.threat_flows ?? "—"}
        />

        <FlowMetric
          icon={Database}
          label="SOURCE DATA"
          value="CIC-IDS2017-DERIVED"
        />
      </div>

      <div className="flow-filter-panel">
        <div className="flow-filter-heading">
          <span>FILTERS</span>
          <button onClick={resetFilters}>
            RESET
          </button>
        </div>

        <div className="flow-filter-row">
          <label>
            <span>THREAT</span>
            <select
              value={threatFilter}
              onChange={(event) => {
                setThreatFilter(event.target.value);
                setPage(1);
              }}
            >
              {threatOptions.map((option) => (
                <option key={option} value={option}>
                  {formatThreat(option)}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>SEVERITY</span>
            <select
              value={severityFilter}
              onChange={(event) => {
                setSeverityFilter(event.target.value);
                setPage(1);
              }}
            >
              {severityOptions.map((option) => (
                <option key={option} value={option}>
                  {formatThreat(option)}
                </option>
              ))}
            </select>
          </label>

          <div className="flow-filter-status">
            SHOWING{" "}
            <strong>{filteredFlows.length}</strong>{" "}
            OF <strong>{allFlows.length}</strong> REPLAY RECORDS
          </div>
        </div>
      </div>

      <div className="flow-panel">
        <div className="special-card-heading">
          <div>
            <span>FLOW INVENTORY</span>
            <h3>Replay Telemetry</h3>
          </div>

          <div className="flow-export-actions">
            <button
              className="secondary-button"
              onClick={exportCSV}
              disabled={!filteredFlows.length}
            >
              <Download size={14} />
              CSV
            </button>

            <button
              className="secondary-button"
              onClick={exportJSON}
              disabled={!filteredFlows.length}
            >
              <Download size={14} />
              JSON
            </button>
          </div>
        </div>

        {paginatedFlows.length > 0 ? (
          <>
            <div className="flow-table-wrap">
              <table className="investigation-table flow-explorer-table">
                <thead>
                  <tr>
                    <th>FLOW</th>
                    <th>EXPECTED</th>
                    <th>PREDICTED</th>
                    <th>CONFIDENCE</th>
                    <th>ALERT</th>
                    <th>SEVERITY</th>
                    <th>LATENCY</th>
                    <th>ACTION</th>
                  </tr>
                </thead>

                <tbody>
                  {paginatedFlows.map((flow, index) => (
                    <tr
                      key={`${flow?.flow_number ?? "flow"}-${index}`}
                      onClick={() => setSelectedFlow(flow)}
                      className="flow-clickable-row"
                    >
                      <td className="mono-cell">
                        #{flow?.flow_number ?? "—"}
                      </td>

                      <td>
                        {formatThreat(flow?.expected_class)}
                      </td>

                      <td>
                        <span className="flow-threat-name">
                          {formatThreat(flow?.predicted_class)}
                        </span>
                      </td>

                      <td className="confidence-cell">
                        {Number(flow?.confidence || 0).toFixed(2)}%
                      </td>

                      <td>
                        <span
                          className={
                            flow?.alert_generated
                              ? "flow-alert-yes"
                              : "flow-alert-no"
                          }
                        >
                          {flow?.alert_generated ? "YES" : "NO"}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`flow-severity ${
                            String(
                              flow?.severity || "BENIGN",
                            ).toLowerCase()
                          }`}
                        >
                          {flow?.severity || "BENIGN"}
                        </span>
                      </td>

                      <td>
                        {Number(
                          flow?.processing_time_ms || 0,
                        ).toFixed(3)}{" "}
                        ms
                      </td>

                      <td>
                        <button
                          className="flow-view-button"
                          onClick={(event) => {
                            event.stopPropagation();
                            setSelectedFlow(flow);
                          }}
                        >
                          VIEW
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flow-pagination">
              <span>
                Showing{" "}
                <strong>
                  {filteredFlows.length
                    ? (safePage - 1) * pageSize + 1
                    : 0}
                </strong>
                –
                <strong>
                  {Math.min(
                    safePage * pageSize,
                    filteredFlows.length,
                  )}
                </strong>{" "}
                of <strong>{filteredFlows.length}</strong>
              </span>

              <div>
                <button
                  className="flow-page-button"
                  disabled={safePage <= 1}
                  onClick={() => setPageSafe(safePage - 1)}
                >
                  <ChevronLeft size={15} />
                </button>

                <span className="flow-page-number">
                  {safePage} / {totalPages}
                </span>

                <button
                  className="flow-page-button"
                  disabled={safePage >= totalPages}
                  onClick={() => setPageSafe(safePage + 1)}
                >
                  <ChevronRight size={15} />
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flow-empty">
            <Network size={28} />
            <strong>
              {allFlows.length
                ? "No flows match the current filters"
                : "No replay flow records currently loaded"}
            </strong>
            <span>
              {allFlows.length
                ? "Adjust the search or reset the filters to view the replay inventory."
                : "Run Flow Replay to populate the real processed-flow inventory for this session."}
            </span>
          </div>
        )}
      </div>

      <div className="flow-secondary-grid">
        <div className="flow-panel">
          <div className="special-card-heading">
            <div>
              <span>MODEL OUTPUT</span>
              <h3>Threat Class Distribution</h3>
            </div>
          </div>

          {classDistribution.length ? (
            <div className="flow-class-distribution">
              {classDistribution.map(([name, count]) => {
                const maxCount = Math.max(
                  ...classDistribution.map(([, value]) => value),
                  1,
                );

                return (
                  <div
                    className="flow-distribution-row"
                    key={name}
                  >
                    <span>{formatThreat(name)}</span>

                    <div>
                      <div
                        style={{
                          width: `${(count / maxCount) * 100}%`,
                        }}
                      />
                    </div>

                    <strong>{count}</strong>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flow-empty compact">
              No classifier records available yet.
            </div>
          )}
        </div>

        <div className="flow-panel">
          <div className="special-card-heading">
            <div>
              <span>SCHEMA SCOPE</span>
              <h3>Available Flow Metadata</h3>
            </div>
          </div>

          <div className="flow-schema-note">
            <strong>Current replay response</strong>
            <p>
              Flow number, expected class, predicted class,
              confidence, alert state, severity and processing
              latency are available in the current result schema.
            </p>

            <span>
              Protocol/IP fields are not exposed by the current
              flow-results response, so this view does not fabricate
              those values.
            </span>

            <small>{protocolUnavailable}</small>
          </div>
        </div>
      </div>

      {selectedFlow && (
        <FlowDetails
          flow={selectedFlow}
          onClose={() => setSelectedFlow(null)}
        />
      )}
    </div>
  );
}

function FlowDetails({ flow, onClose }) {
  const evidence = buildFlowEvidence(flow);

  return (
    <div className="flow-modal-backdrop" onClick={onClose}>
      <div
        className="flow-modal"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flow-modal-header">
          <div>
            <span>FLOW DETAILS</span>
            <h3>
              Flow #{flow?.flow_number ?? "—"}
            </h3>
          </div>

          <button
            className="flow-modal-close"
            onClick={onClose}
            aria-label="Close flow details"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flow-detail-grid">
          <FlowDetail
            label="FLOW NUMBER"
            value={flow?.flow_number ?? "—"}
          />
          <FlowDetail
            label="EXPECTED CLASS"
            value={formatThreat(flow?.expected_class)}
          />
          <FlowDetail
            label="PREDICTED CLASS"
            value={formatThreat(flow?.predicted_class)}
          />
          <FlowDetail
            label="CONFIDENCE"
            value={`${Number(flow?.confidence || 0).toFixed(2)}%`}
          />
          <FlowDetail
            label="ALERT GENERATED"
            value={flow?.alert_generated ? "YES" : "NO"}
          />
          <FlowDetail
            label="SEVERITY"
            value={flow?.severity || "BENIGN"}
          />
          <FlowDetail
            label="PROCESSING LATENCY"
            value={`${Number(
              flow?.processing_time_ms || 0,
            ).toFixed(3)} ms`}
          />
          <FlowDetail
            label="REPLAY SOURCE"
            value="CIC-IDS2017-DERIVED"
          />
        </div>

        <div className="flow-evidence-panel">
          <div className="flow-evidence-heading">
            <div>
              <span>MODEL / DETECTOR SIGNALS</span>
              <strong>SUPPORTING EVIDENCE</strong>
            </div>

            <span>
              {evidence.length} INDICATOR
              {evidence.length === 1 ? "" : "S"}
            </span>
          </div>

          {evidence.length > 0 ? (
            <div className="flow-evidence-list">
              {evidence.map((item, index) => (
                <div
                  className="flow-evidence-item"
                  key={`${item.label}-${index}`}
                >
                  <span>•</span>

                  <div>
                    <strong>{item.label}</strong>
                    <small>{item.value}</small>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flow-evidence-empty">
              <strong>
                No additional detector evidence in this flow record.
              </strong>
              <span>
                The current replay response exposes classifier output,
                confidence, alert state, severity and latency.
              </span>
            </div>
          )}
        </div>

        <div className="flow-detail-note">
          <strong>PASSIVE / READ-ONLY</strong>
          <span>
            This view displays metadata produced by the replay
            inference pipeline. No probe, reconnect, mitigation,
            or payload decryption is performed.
          </span>
        </div>
      </div>
    </div>
  );
}


function buildFlowEvidence(flow) {
  const items = [];

  const rawEvidence =
    flow?.supporting_evidence ||
    flow?.evidence;

  if (
    rawEvidence &&
    typeof rawEvidence === "object" &&
    !Array.isArray(rawEvidence)
  ) {
    Object.entries(rawEvidence).forEach(([key, value]) => {
      if (
        value !== null &&
        value !== undefined &&
        value !== ""
      ) {
        items.push({
          label: formatEvidenceLabel(key),
          value: formatEvidenceValue(value),
        });
      }
    });
  }

  if (!items.length) {
    items.push(
      {
        label: "Expected Class",
        value: formatThreat(flow?.expected_class),
      },
      {
        label: "Predicted Class",
        value: formatThreat(flow?.predicted_class),
      },
      {
        label: "Confidence",
        value: `${Number(
          flow?.confidence || 0,
        ).toFixed(2)}%`,
      },
      {
        label: "Alert State",
        value: flow?.alert_generated
          ? "Alert generated"
          : "No alert generated",
      },
      {
        label: "Severity",
        value: flow?.severity || "BENIGN",
      },
      {
        label: "NTRO Category",
        value: getNtroCategory(
          flow?.predicted_class,
        ),
      },
    );
  }

  return items;
}

function getNtroCategory(name) {
  const value = String(name || "").toUpperCase();

  const mapping = {
    DDOS: "Volumetric / Protocol DDoS",
    DOS: "Volumetric / Protocol DDoS",
    PORTSCAN: "Reconnaissance / Port Scanning",
    BOT: "Botnet C2 Beaconing",
    BOT_C2: "Botnet C2 Beaconing",
    DGA: "DGA / DNS Tunnelling",
    DNS_TUNNEL: "DGA / DNS Tunnelling",
    DNS_RECORD_ANOMALY: "DNS Anomaly",
    EXFILTRATION: "Data Exfiltration",
    BRUTE_FORCE: "Additional ML Class",
    WEB_ATTACK: "Additional ML Class",
  };

  return mapping[value] || "Additional ML Class";
}

function formatEvidenceLabel(key) {
  return String(key || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase(),
    );
}

function formatEvidenceValue(value) {
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? value.toLocaleString()
      : Number(value).toFixed(3);
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  return String(value);
}

function FlowDetail({ label, value }) {
  return (
    <div className="flow-detail-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function FlowMetric({ icon: Icon, label, value }) {
  return (
    <div className="flow-metric">
      <div>
        <Icon size={19} />
      </div>

      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatThreat(value) {
  if (!value) return "—";

  const mapping = {
    DDOS: "DDoS",
    DOS: "DoS",
    PORTSCAN: "PortScan",
    BOT: "Bot C2",
    BOT_C2: "Bot C2",
    BRUTE_FORCE: "Brute Force",
    WEB_ATTACK: "Web Attack",
    DGA: "DGA",
    DNS_TUNNEL: "DNS Tunnel",
    DNS_RECORD_ANOMALY: "DNS Record Anomaly",
    EXFILTRATION: "Exfiltration",
  };

  return mapping[String(value).toUpperCase()] || value;
}

function csvCell(value) {
  const stringValue =
    value === null || value === undefined
      ? ""
      : String(value);

  return `"${stringValue.replace(/"/g, '""')}"`;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  URL.revokeObjectURL(url);
}

export default FlowsPage;
