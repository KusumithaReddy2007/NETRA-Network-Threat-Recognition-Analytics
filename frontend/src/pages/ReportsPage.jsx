import {
  Download,
  FileBarChart,
  FileText,
  ShieldCheck,
} from "lucide-react";

function ReportsPage({ analytics }) {
  function exportReport() {
    const report = {
      generated_at: new Date().toISOString(),
      source: "NETRA current analytics window",
      analytics: analytics || {},
    };

    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "netra-security-report.json";
    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
  }

  return (
    <div className="special-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            SECURITY REPORTING
          </div>

          <h1>Reports</h1>

          <p>
            Generate a security summary from the current
            NETRA analysis window.
          </p>
        </div>

        <button
          className="primary-button"
          onClick={exportReport}
          disabled={!analytics}
        >
          <Download size={16} />
          EXPORT REPORT
        </button>
      </div>

      <div className="report-sheet">
        <div className="report-header">
          <div>
            <div className="report-brand">
              <ShieldCheck size={23} />
              NETRA
            </div>

            <span>
              NETWORK THREAT RECOGNITION & ANALYTICS
            </span>
          </div>

          <FileBarChart size={28} />
        </div>

        <div className="report-title">
          <span>SECURITY ANALYSIS REPORT</span>
          <h2>Network Threat Summary</h2>
          <p>
            Generated from the current NETRA analytics
            window.
          </p>
        </div>

        <div className="report-grid">
          <ReportValue
            label="TOTAL FLOWS"
            value={analytics?.total_flows ?? "—"}
          />

          <ReportValue
            label="BENIGN FLOWS"
            value={analytics?.benign_flows ?? "—"}
          />

          <ReportValue
            label="THREAT FLOWS"
            value={analytics?.threat_flows ?? "—"}
          />

          <ReportValue
            label="THREAT RATE"
            value={`${analytics?.threat_percentage ?? 0}%`}
          />
        </div>

        <div className="report-section">
          <h3>Detection Summary</h3>

          {Object.entries(
            analytics?.threat_types || {}
          ).map(([name, value]) => (
            <div
              className="report-row"
              key={name}
            >
              <span>{name}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ReportValue({ label, value }) {
  return (
    <div className="report-value">
      <FileText size={17} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default ReportsPage;
