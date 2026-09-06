import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Eye,
  Filter,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

function ThreatsPage({ alerts }) {
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesFilter =
        filter === "ALL" ||
        alert.threat_class === filter;

      const text = `${alert.threat_class} ${alert.flow_id} ${alert.alert_id}`.toLowerCase();

      return (
        matchesFilter &&
        text.includes(search.toLowerCase())
      );
    });
  }, [alerts, filter, search]);

  const types = [
    "ALL",
    ...new Set(alerts.map((a) => a.threat_class)),
  ];

  return (
    <div className="special-page">
      <PageHeader />

      <div className="threat-center">
        <div className="threat-toolbar">
          <div className="filter-title">
            <ShieldAlert size={19} />
            <div>
              <strong>THREAT CENTER</strong>
              <span>
                {filtered.length} visible detections
              </span>
            </div>
          </div>

          <div className="threat-search">
            <Search size={16} />
            <input
              value={search}
              onChange={(e) =>
                setSearch(e.target.value)
              }
              placeholder="Search alert ID, flow ID, threat..."
            />
          </div>
        </div>

        <div className="filter-row">
          <Filter size={14} />

          {types.map((type) => (
            <button
              key={type}
              className={
                filter === type ? "filter-active" : ""
              }
              onClick={() => setFilter(type)}
            >
              {type.replaceAll("_", " ")}
            </button>
          ))}
        </div>

        <div className="threat-table-panel">
          <table className="investigation-table">
            <thead>
              <tr>
                <th>ALERT ID</th>
                <th>THREAT</th>
                <th>FLOW ID</th>
                <th>TIME</th>
                <th>SEVERITY</th>
                <th>CONFIDENCE</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {filtered.map((alert, index) => (
                <motion.tr
                  key={
                    alert.alert_id || index
                  }
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                >
                  <td className="mono-cell">
                    {alert.alert_id}
                  </td>

                  <td>
                    <span className="table-threat">
                      {alert.threat_class}
                    </span>
                  </td>

                  <td className="mono-cell">
                    {alert.flow_id}
                  </td>

                  <td>
                    {formatTime(alert.timestamp)}
                  </td>

                  <td>
                    <Severity
                      value={alert.severity}
                    />
                  </td>

                  <td className="confidence-cell">
                    {alert.confidence}%
                  </td>

                  <td>
                    <button
                      className="investigate-button"
                      onClick={() =>
                        setSelected(alert)
                      }
                    >
                      <Eye size={15} />
                      INVESTIGATE
                    </button>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>

          {!filtered.length && (
            <div className="threat-empty">
              <AlertTriangle size={24} />
              <strong>No matching detections</strong>
              <span>
                Try another threat filter or search.
              </span>
            </div>
          )}
        </div>
      </div>

      <AnimatePresence>
        {selected && (
          <motion.div
            className="detail-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setSelected(null)}
          >
            <motion.aside
              className="detail-drawer"
              initial={{ x: 430 }}
              animate={{ x: 0 }}
              exit={{ x: 430 }}
              transition={{ type: "spring", damping: 27 }}
              onClick={(e) => e.stopPropagation()}
            >
              <button
                className="drawer-close"
                onClick={() => setSelected(null)}
              >
                <X size={18} />
              </button>

              <div className="drawer-eyebrow">
                SECURITY EVENT
              </div>

              <h2>{selected.threat_class}</h2>

              <Severity
                value={selected.severity}
              />

              <div className="drawer-grid">
                <Detail label="ALERT ID" value={selected.alert_id} />
                <Detail label="FLOW ID" value={selected.flow_id} />
                <Detail label="TIMESTAMP" value={selected.timestamp} />
                <Detail
                  label="CONFIDENCE"
                  value={`${selected.confidence}%`}
                />
              </div>

              <div className="evidence">
                <div className="evidence-heading">
                  <strong>SUPPORTING EVIDENCE</strong>
                  <span>DETECTION EVIDENCE</span>
                </div>

                {Object.entries(
                  selected.supporting_evidence || {}
                ).map(([key, value]) => (
                  <div className="evidence-row" key={key}>
                    <span>{key.replaceAll("_", " ")}</span>
                    <strong>{String(value)}</strong>
                  </div>
                ))}
              </div>
            </motion.aside>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function PageHeader() {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          THREAT INVESTIGATION
        </div>

        <h1>Threat Center</h1>

        <p>
          Investigate standardized NETRA security
          detections and their supporting evidence.
        </p>
      </div>
    </div>
  );
}

function Severity({ value }) {
  const text = String(value || "HIGH").toUpperCase();

  return (
    <span
      className={`severity-badge ${text.toLowerCase()}`}
    >
      {text}
    </span>
  );
}

function Detail({ label, value }) {
  return (
    <div className="drawer-detail">
      <span>{label}</span>
      <strong>{value || "—"}</strong>
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

export default ThreatsPage;
