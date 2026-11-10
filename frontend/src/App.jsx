import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  Bot,
  ChevronDown,
  Eye,
  FileBarChart,
  Home,
  Menu,
  Network,
  Radar,
  Search,
  Settings,
  ShieldAlert,
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";

import {
  getAnalytics,
  replayTraffic,
  healthCheck,
} from "./services/api";

import DashboardPage from "./pages/DashboardPage";
import LiveMonitoringPage from "./pages/LiveMonitoringPage";
import LiveTrafficPage from "./pages/LiveTrafficPage";
import ThreatsPage from "./pages/ThreatsPage";
import AnalyticsPage from "./pages/AnalyticsPage";
import FlowsPage from "./pages/FlowsPage";
import AlertsPage from "./pages/AlertsPage";
import ReportsPage from "./pages/ReportsPage";
import ModelPage from "./pages/ModelPage";
import SettingsPage from "./pages/SettingsPage";
import TrafficArchitecturePage from "./pages/TrafficArchitecturePage";

import "./App.css";

const NAVIGATION = [
  { label: "Dashboard", icon: Home },
  { label: "Live Monitoring", icon: Radar },
  { label: "Live Traffic", icon: Activity },
  { label: "Traffic Architecture", icon: Network },
  { label: "Threats", icon: ShieldAlert },
  { label: "Analytics", icon: BarChart3 },
  { label: "Flows", icon: Network },
  { label: "Alerts", icon: ShieldAlert },
  { label: "Reports", icon: FileBarChart },
  { label: "Model", icon: Bot },
  { label: "Settings", icon: Settings },
];

function formatTime(timestamp) {
  if (!timestamp) return "—";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function App() {
  const [activePage, setActivePage] =
    useState("Dashboard");

  const [mobileOpen, setMobileOpen] =
    useState(false);

  const [authenticated, setAuthenticated] =
    useState(false);

  const [analytics, setAnalytics] =
    useState(null);

  const [alerts, setAlerts] = useState([]);
  const [unifiedAlerts, setUnifiedAlerts] = useState([]);
  const [flowResults, setFlowResults] = useState([]);
  const [globalSearch, setGlobalSearch] = useState("");

  const [online, setOnline] = useState(false);
    useState(false);

  const [booting, setBooting] =
    useState(true);

  const [dataLoading, setDataLoading] =
    useState(true);

  const [replaying, setReplaying] =
    useState(false);

  const [error, setError] =
    useState("");

  function onAlertsDetected(newAlerts) {
    if (!Array.isArray(newAlerts) || newAlerts.length === 0) {
      return;
    }

    const normalizedAlerts = newAlerts
      .filter((alert) => alert && alert.triggered === true)
      .map((alert, index) => {
        const evidence = alert.evidence || {};

        const sourceIp =
          evidence.source_ip ||
          evidence.src_ip ||
          "unknown";

        const destinationIp =
          evidence.destination_ip ||
          evidence.dst_ip ||
          "unknown";

        const sourcePort =
          evidence.source_port ??
          evidence.src_port ??
          "";

        const destinationPort =
          evidence.destination_port ??
          evidence.dst_port ??
          "";

        const uid =
          evidence.uid ||
          `${sourceIp}-${sourcePort}-${destinationIp}-${destinationPort}`;

        const timestamp =
          alert.timestamp ||
          evidence.timestamp ||
          new Date().toISOString();

        const confidence = Math.round(
          Number(alert.score || 0) <= 1
            ? Number(alert.score || 0) * 100
            : Number(alert.score || 0)
        );

        return {
          source: "TELEMETRY",
          alert_id:
            alert.alert_id ||
            `NETRA-${Date.now().toString(36).toUpperCase()}-${index}`,
          threat_class:
            alert.threat_class || "UNKNOWN",
          flow_id:
            alert.flow_id ||
            `${alert.detector || "NETRA"}-${uid}`,
          timestamp,
          severity:
            alert.severity ||
            (confidence >= 90
              ? "CRITICAL"
              : confidence >= 70
                ? "HIGH"
                : "MEDIUM"),
          confidence,
          supporting_evidence: {
            detector: alert.detector || "NETRA",
            score: alert.score,
            source_ip: sourceIp,
            destination_ip: destinationIp,
            source_port: sourcePort,
            destination_port: destinationPort,
            ...evidence,
          },
        };
      });

    if (normalizedAlerts.length === 0) {
      return;
    }

    setUnifiedAlerts((current) => {
      const combined = [...current, ...normalizedAlerts];

      const unique = Array.from(
        new Map(
          combined.map((alert, index) => [
            alert.alert_id ||
              `${alert.threat_class}-${alert.flow_id}-${alert.timestamp}-${index}`,
            alert,
          ])
        ).values()
      );

      const sorted = unique.sort(
        (a, b) =>
          new Date(b.timestamp || 0) -
          new Date(a.timestamp || 0)
      );

      window.sessionStorage.setItem(
        "netra_unified_alerts",
        JSON.stringify(sorted)
      );

      return sorted;
    });
  }

  async function loadAnalytics() {
    try {
      setDataLoading(true);
      setError("");

      const result =
        await getAnalytics(100);

      if (result?.analytics) {
        setAnalytics(result.analytics);
        setOnline(true);
      }

      const savedAlerts =
        window.sessionStorage.getItem("netra_latest_alerts");

      if (savedAlerts) {
        try {
          const parsedAlerts = JSON.parse(savedAlerts);
          const validAlerts =
            Array.isArray(parsedAlerts)
              ? parsedAlerts
              : [];

          setAlerts(validAlerts);

          setUnifiedAlerts((current) => {
            const nonFlowAlerts = current.filter(
              (alert) => alert.source !== "FLOW"
            );

            const flowAlerts = validAlerts.map(
              (alert) => ({
                ...alert,
                source: "FLOW",
              })
            );

            const sorted = [...nonFlowAlerts, ...flowAlerts].sort(
              (a, b) =>
                new Date(b.timestamp || 0) -
                new Date(a.timestamp || 0)
            );

            window.sessionStorage.setItem(
              "netra_unified_alerts",
              JSON.stringify(sorted)
            );

            return sorted;
          });
        } catch {
          window.sessionStorage.removeItem(
            "netra_latest_alerts"
          );
          setAlerts([]);
        }
      }
    } catch (err) {
      console.error(
        "NETRA analytics error:",
        err
      );

      setOnline(false);

      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Analytics service unavailable"
      );
    } finally {
      setDataLoading(false);
    }
  }

  async function runReplay() {
    if (replaying) return;

    try {
      setReplaying(true);
      setError("");

      const result =
        await replayTraffic(100, 0);

      const latestAlerts =
        Array.isArray(result?.alerts)
          ? result.alerts
          : [];

      const latestFlowResults =
        Array.isArray(result?.results)
          ? result.results
          : [];

      setAlerts(latestAlerts);
      setFlowResults(latestFlowResults);

      window.sessionStorage.setItem(
        "netra_flow_results",
        JSON.stringify(latestFlowResults)
      );

      window.sessionStorage.setItem(
        "netra_latest_alerts",
        JSON.stringify(latestAlerts)
      );

      await loadAnalytics();
    } catch (err) {
      console.error(
        "NETRA replay error:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Replay failed"
      );
    } finally {
      setReplaying(false);
    }
  }

  useEffect(() => {
    const timer = setTimeout(() => {
      setBooting(false);
    }, 1700);

    healthCheck()
      .then(() => setOnline(true))
      .catch(() => setOnline(false));

    loadAnalytics();

    return () =>
      clearTimeout(timer);
  }, []);

  const threatTypes = useMemo(() => {
    return Object.entries(
      analytics?.threat_types || {}
    )
      .map(([name, value]) => ({
        name,
        value: Number(value),
      }))
      .sort(
        (a, b) => b.value - a.value
      );
  }, [analytics]);

  const severity =
    analytics?.severity_breakdown || {};

  const searchResults = useMemo(() => {
    const query = globalSearch.trim().toLowerCase();

    if (!query) {
      return [];
    }

    const results = [];

    unifiedAlerts.forEach((alert) => {
      const evidenceText = Object.values(
        alert.supporting_evidence || {}
      )
        .flatMap((value) =>
          Array.isArray(value) ? value : [value]
        )
        .join(" ");

      const haystack = [
        alert.alert_id,
        alert.threat_class,
        alert.flow_id,
        alert.severity,
        alert.timestamp,
        evidenceText,
      ]
        .join(" ")
        .toLowerCase();

      if (haystack.includes(query)) {
        results.push({
          type: "THREAT",
          title: alert.threat_class || "UNKNOWN",
          subtitle:
            alert.alert_id ||
            alert.flow_id ||
            "Security detection",
          identifier:
            alert.flow_id || alert.alert_id || "NETRA",
        });
      }
    });

    flowResults.forEach((flow) => {
      const haystack = [
        flow.flow_number,
        flow.expected_class,
        flow.predicted_class,
        flow.confidence,
        flow.severity,
        flow.alert_generated,
      ]
        .join(" ")
        .toLowerCase();

      if (haystack.includes(query)) {
        results.push({
          type: "FLOW",
          title:
            flow.predicted_class ||
            flow.expected_class ||
            "FLOW",
          subtitle: `Flow #${flow.flow_number}`,
          identifier: `Flow #${flow.flow_number}`,
        });
      }
    });

    return results.slice(0, 8);
  }, [globalSearch, unifiedAlerts, flowResults]);

  const page = renderPage({
    activePage,
    analytics,
    alerts,
    unifiedAlerts,
    flowResults,
    onAlertsDetected,
    threatTypes,
    severity,
    replaying,
    dataLoading,
    error,
    runReplay,
  });

  if (booting) {
    return <BootScreen />;
  }

  if (!authenticated) {
    return (
      <LoginPage
        onLogin={() => {
          setAuthenticated(true);
        }}
      />
    );
  }

  return (
    <div className="netra-app">
      <CyberAtmosphere />

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            className="mobile-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() =>
              setMobileOpen(false)
            }
          />
        )}
      </AnimatePresence>

      <aside
        className={`sidebar ${
          mobileOpen
            ? "sidebar-open"
            : ""
        }`}
      >
        <div className="brand">
          <div className="brand-mark">
            <Eye size={24} />
            <span className="brand-ring" />
          </div>

          <div>
            <div className="brand-name">
              NETRA
            </div>

            <div className="brand-subtitle">
              NETWORK THREAT RECOGNITION
            </div>
          </div>
        </div>

        <div className="sidebar-label">
          OPERATIONS
        </div>

        <nav className="navigation">
          {NAVIGATION.map((item) => {
            const Icon = item.icon;

            const active =
              activePage === item.label;

            return (
              <button
                key={item.label}
                className={`nav-item ${
                  active
                    ? "active"
                    : ""
                }`}
                onClick={() => {
                  setActivePage(
                    item.label
                  );
                  setMobileOpen(false);
                }}
              >
                <span className="nav-icon">
                  <Icon size={18} />
                </span>

                <span className="nav-text">
                  {item.label}
                </span>

                {item.label ===
                  "Threats" &&
                  unifiedAlerts.length >
                    0 && (
                    <span className="nav-badge">
                      {unifiedAlerts.length}
                    </span>
                  )}

                {item.label ===
                  "Alerts" &&
                  alerts.length >
                    0 && (
                    <span className="nav-badge">
                      {alerts.length}
                    </span>
                  )}

                {active && (
                  <span className="nav-glow" />
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-spacer" />

        <div className="system-panel">
          <div className="panel-header">
            <span>
              SYSTEM STATUS
            </span>

            <Activity size={15} />
          </div>

          <StatusRow
            label="AI ENGINE"
            value={
              online
                ? "ONLINE"
                : "OFFLINE"
            }
            online={online}
          />

          <StatusRow
            label="STREAM PROCESSOR"
            value={
              online
                ? "ONLINE"
                : "OFFLINE"
            }
            online={online}
          />

          <StatusRow
            label="MODEL"
            value="ACTIVE"
            online
          />

          <StatusRow
            label="DATASET"
            value="CIC-IDS2017"
          />

          <StatusRow
            label="MODE"
            value="PASSIVE"
          />
        </div>

        <div className="sidebar-foot">
          <span>NETRA CORE</span>
          <span>v1.0.0</span>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu"
              onClick={() =>
                setMobileOpen(
                  !mobileOpen
                )
              }
            >
              <Menu size={22} />
            </button>

            <div className="breadcrumb">
              <span>
                NETRA
              </span>
              <i>/</i>
              <strong>
                {activePage}
              </strong>
            </div>
          </div>

          <div className="global-search-wrap">
            <div className="global-search">
              <Search size={17} />

              <input
                value={globalSearch}
                onChange={(e) =>
                  setGlobalSearch(e.target.value)
                }
                placeholder="Search threats, IPs, flows..."
                aria-label="Global search"
              />

              <kbd>
                Ctrl K
              </kbd>
            </div>

            {globalSearch.trim() && (
              <div className="global-search-results">
                {searchResults.length > 0 ? (
                  searchResults.map((result, index) => (
                    <button
                      key={`${result.type}-${result.identifier}-${index}`}
                      className="global-search-result"
                      onClick={() => {
                        setActivePage(
                          result.type === "THREAT"
                            ? "Threats"
                            : "Flows"
                        );
                        setGlobalSearch("");
                      }}
                    >
                      <span className="search-result-type">
                        {result.type}
                      </span>

                      <span className="search-result-main">
                        <strong>{result.title}</strong>
                        <small>{result.subtitle}</small>
                      </span>
                    </button>
                  ))
                ) : (
                  <div className="global-search-empty">
                    <Search size={15} />
                    <span>No matching NETRA records</span>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="topbar-right">
            <div className="connection">
              <span />
              {online
                ? "SYSTEM ONLINE"
                : "SYSTEM OFFLINE"}
            </div>




            <div className="user-block">
              <div className="user-avatar">
                A
              </div>

              <div>
                <strong>
                  Admin
                </strong>

                <span>
                  Security Operator
                </span>
              </div>

              <button
                type="button"
                className="admin-logout"
                onClick={() => {
                  setAuthenticated(false);
                }}
                title="Log out"
              >
                LOGOUT
              </button>

              <ChevronDown
                size={16}
              />
            </div>
          </div>
        </header>

        <main className="content">
          <AnimatePresence mode="wait">
            <motion.div
              key={activePage}
              initial={{
                opacity: 0,
                y: 10,
              }}
              animate={{
                opacity: 1,
                y: 0,
              }}
              exit={{
                opacity: 0,
                y: -8,
              }}
              transition={{
                duration: 0.22,
              }}
            >
              {page}
            </motion.div>
          </AnimatePresence>

          <footer className="app-footer">
            <div>
              NETRA SECURITY ENGINE
              <span>•</span>
              PASSIVE MONITORING
            </div>

            <div>
              READ-ONLY DETECTION MODE
            </div>
          </footer>
        </main>
      </div>
    </div>
  );
}

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  function handleSubmit(event) {
    event.preventDefault();

    if (
      username.trim().toLowerCase() === "admin" &&
      password === "netra@2026"
    ) {
      setError("");
      onLogin();
      return;
    }

    setError("Invalid administrator credentials.");
  }

  return (
    <div className="login-screen">
      <div className="login-grid" />

      <div className="login-card">
        <div className="login-brand">
          <div className="login-brand-mark">
            <Eye size={25} />
          </div>

          <div>
            <strong>NETRA</strong>
            <span>NETWORK THREAT RECOGNITION</span>
          </div>
        </div>

        <div className="login-eyebrow">
          AUTHENTICATED OPERATIONS
        </div>

        <h1>Security Operator Login</h1>

        <p>
          Sign in to access the NETRA threat detection
          and security operations console.
        </p>

        <form onSubmit={handleSubmit}>
          <label>
            ADMIN USERNAME
            <input
              type="text"
              value={username}
              onChange={(event) =>
                setUsername(event.target.value)
              }
              placeholder="Enter username"
              autoComplete="username"
              autoFocus
            />
          </label>

          <label>
            PASSWORD
            <input
              type="password"
              value={password}
              onChange={(event) =>
                setPassword(event.target.value)
              }
              placeholder="Enter password"
              autoComplete="current-password"
            />
          </label>

          {error && (
            <div className="login-error">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="primary-button login-button"
          >
            <ShieldAlert size={17} />
            ACCESS NETRA
          </button>
        </form>

        <div className="login-security-note">
          PASSIVE • READ-ONLY • AUTHORIZED ACCESS
        </div>
      </div>
    </div>
  );
}

function renderPage({
  activePage,
  analytics,
  alerts,
  unifiedAlerts,
  flowResults,
  onAlertsDetected,
  threatTypes,
  severity,
  replaying,
  dataLoading,
  error,
  runReplay,
}) {
  switch (activePage) {
    case "Live Traffic":
      return <LiveTrafficPage />;

    case "Live Monitoring":
      return (
        <LiveMonitoringPage
          analytics={analytics}
          alerts={alerts}
          runReplay={runReplay}
          replaying={replaying}
          onAlertsDetected={onAlertsDetected}
        />
      );

    case "Traffic Architecture":
      return (
        <TrafficArchitecturePage
          flowResults={flowResults}
          runReplay={runReplay}
          replaying={replaying}
        />
      );

    case "Threats":
      return (
        <ThreatsPage
          alerts={unifiedAlerts}
        />
      );

    case "Analytics":
      return (
        <AnalyticsPage
          analytics={analytics}
          alerts={unifiedAlerts}
        />
      );

    case "Flows":
      return (
        <FlowsPage
          analytics={analytics}
          flowResults={flowResults}
        />
      );

    case "Alerts":
      return (
        <AlertsPage
          alerts={unifiedAlerts}
        />
      );

    case "Reports":
      return (
        <ReportsPage
          analytics={analytics}
        />
      );

    case "Model":
      return (
        <ModelPage
          analytics={analytics}
        />
      );

    case "Settings":
      return (
        <SettingsPage />
      );

    default:
      return (
        <DashboardPage
          analytics={analytics}
          alerts={alerts}
          threatTypes={threatTypes}
          severity={severity}
          replaying={replaying}
          dataLoading={dataLoading}
          error={error}
          runReplay={runReplay}
        />
      );
  }
}

function StatusRow({
  label,
  value,
  online = false,
}) {
  return (
    <div className="status-row">
      <span>{label}</span>

      <strong
        className={
          online ? "online" : ""
        }
      >
        {online && <i />}
        {value}
      </strong>
    </div>
  );
}

function BootScreen() {
  return (
    <motion.div
      className="boot-screen"
      initial={{
        opacity: 1,
      }}
      exit={{
        opacity: 0,
        scale: 1.03,
      }}
    >
      <div className="boot-grid" />
      <div className="boot-scan-beam" />

      <div className="boot-core">
        <motion.div
          className="boot-orbit orbit-one"
          animate={{
            rotate: 360,
          }}
          transition={{
            duration: 2.2,
            repeat: Infinity,
            ease: "linear",
          }}
        />

        <motion.div
          className="boot-orbit orbit-two"
          animate={{
            rotate: -360,
          }}
          transition={{
            duration: 3.5,
            repeat: Infinity,
            ease: "linear",
          }}
        />

        <motion.div
          className="boot-orbit orbit-three"
          animate={{
            rotate: 360,
            scale: [1, 1.05, 1],
          }}
          transition={{
            rotate: {
              duration: 5,
              repeat: Infinity,
              ease: "linear",
            },
            scale: {
              duration: 1.8,
              repeat: Infinity,
            },
          }}
        />

        <motion.div
          className="boot-logo"
          animate={{
            scale: [1, 1.08, 1],
          }}
          transition={{
            duration: 1.5,
            repeat: Infinity,
          }}
        >
          <Eye size={40} />
        </motion.div>
      </div>

      <motion.div
        className="boot-brand"
        initial={{
          opacity: 0,
          y: 25,
        }}
        animate={{
          opacity: 1,
          y: 0,
        }}
      >
        NETRA
      </motion.div>

      <div className="boot-title">
        NETWORK THREAT RECOGNITION
        <span>
          {" "}
          &amp; ANALYTICS
        </span>
      </div>

      <div className="boot-status">
        <span />
        INITIALIZING SECURITY OPERATIONS CENTER
      </div>

      <div className="boot-progress">
        <motion.div
          initial={{
            width: 0,
          }}
          animate={{
            width: "100%",
          }}
          transition={{
            duration: 1.55,
          }}
        />
      </div>

      <div className="boot-footer">
        <span>
          PASSIVE MONITORING
        </span>
        <span>
          AI THREAT DETECTION
        </span>
        <span>
          READ-ONLY MODE
        </span>
      </div>
    </motion.div>
  );
}

function CyberAtmosphere() {
  return (
    <>
      <div className="ambient ambient-cyan" />
      <div className="ambient ambient-blue" />
      <div className="ambient ambient-red" />
      <div className="cyber-grid" />
      <div className="scanlines" />
    </>
  );
}

export default App;
