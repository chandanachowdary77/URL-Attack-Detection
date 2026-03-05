import React, { useState } from "react";
import "./Export.css";
import { authFetch } from "../api";   // ✅ ADDED

const Export = () => {
  const [format, setFormat] = useState("csv");
  const [attackType, setAttackType] = useState("");
  const [severity, setSeverity] = useState("");

  const handleExport = async (e) => {   // ✅ made async
    e.preventDefault();

    let url = `http://localhost:5000/api/export?format=${format}`;

    if (attackType) url += `&attack_type=${attackType}`;
    if (severity) url += `&severity=${severity}`;

    try {
      const response = await authFetch(url);   // ✅ AUTH FETCH

      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `attacks_export.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();

    } catch (error) {
      alert("Export failed");
    }
  };

  return (
    <div className="export-container">

      <div className="export-header">
        <h2 className="export-title">
          <i className="fas fa-download export-icon"></i>
          Export Security Data
        </h2>

        <p className="export-subtitle">
          Download attack detection results in multiple formats
        </p>
      </div>

      <div className="row g-4">

        {/* Export Form */}
        <div className="col-md-6">
          <div className="card p-4 shadow-sm">

            <h5 className="mb-4">
              <i className="fas fa-file-export"></i> Export Options
            </h5>

            <form onSubmit={handleExport}>

              {/* Format */}
              <div className="mb-3">
                <label className="form-label fw-bold">
                  Export Format:
                </label>

                <div className="form-check">
                  <input
                    type="radio"
                    className="form-check-input"
                    value="csv"
                    checked={format === "csv"}
                    onChange={(e) => setFormat(e.target.value)}
                  />
                  <label className="form-check-label">
                    CSV
                  </label>
                </div>

                <div className="form-check">
                  <input
                    type="radio"
                    className="form-check-input"
                    value="json"
                    checked={format === "json"}
                    onChange={(e) => setFormat(e.target.value)}
                  />
                  <label className="form-check-label">
                    JSON
                  </label>
                </div>
              </div>

              {/* Attack Type */}
              <div className="mb-3">
                <label className="form-label fw-bold">
                  Filter by Attack Type:
                </label>
                <select
                  className="form-select"
                  value={attackType}
                  onChange={(e) => setAttackType(e.target.value)}
                >
                  <option value="">All Attack Types</option>
                  <option value="sql_injection">SQL Injection</option>
                  <option value="xss">XSS</option>
                  <option value="directory_traversal">Directory Traversal</option>
                  <option value="command_injection">Command Injection</option>
                  <option value="ssrf">SSRF</option>
                  <option value="lfi">Local File Inclusion</option>
                  <option value="credential_stuffing">Credential Stuffing</option>
                  <option value="typosquatting">Typosquatting</option>
                </select>
              </div>

              {/* Severity */}
              <div className="mb-3">
                <label className="form-label fw-bold">
                  Filter by Severity:
                </label>
                <select
                  className="form-select"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  <option value="">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <button type="submit" className="export-btn">
                <i className="fas fa-download"></i> Export Data
              </button>

            </form>
          </div>
        </div>

        {/* Info Card */}
        <div className="col-md-6">
          <div className="card p-4 shadow-sm">

            <h5 className="mb-4">
              <i className="fas fa-info-circle"></i> Export Information
            </h5>

            <h6 className="fw-bold">CSV Format</h6>
            <p className="text-muted">
              Ideal for Excel or spreadsheets. Contains all attack data with headers.
            </p>

            <h6 className="fw-bold">JSON Format</h6>
            <p className="text-muted">
              Perfect for programmatic analysis and integration.
            </p>

            <h6 className="fw-bold">Exported Fields</h6>
            <ul className="text-muted">
              <li>ID</li>
              <li>Timestamp</li>
              <li>Source IP Address</li>
              <li>URL</li>
              <li>HTTP Method</li>
              <li>Attack Type</li>
              <li>Severity Level</li>
              <li>Malicious Status</li>
              <li>Success Status</li>
              <li>Confidence Score</li>
              <li>Pattern Matched</li>
              <li>User Agent</li>
              <li>Record Created At</li>
            </ul>

            <div className="alert alert-info mt-3">
              <strong>Tip:</strong> Use filters to export specific subsets.
            </div>

          </div>
        </div>

      </div>

    </div>
  );
};

export default Export;