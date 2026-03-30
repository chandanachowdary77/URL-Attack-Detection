import React, { useEffect, useState } from "react";
import { authFetch } from "../api";
import "./Attacks.css";

const Attacks = () => {
  const [attacks, setAttacks] = useState([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);

  // Modal State
  const [selectedExplanation, setSelectedExplanation] = useState(null);
  const [loadingExplanation, setLoadingExplanation] = useState(false);

  useEffect(() => {
    loadAttacks();
  }, []);

  const loadAttacks = async () => {
    try {
      const response = await authFetch("http://16.171.39.9:5000/api/history");
      const data = await response.json();
      setAttacks(data.attacks || []);
    } catch (error) {
      console.error("Error loading attacks:", error);
    }
    setLoading(false);
  };

  const filteredAttacks = filter
    ? attacks.filter((attack) => attack.attack_type === filter)
    : attacks;

  const fetchExplanation = async (url) => {
    setLoadingExplanation(true);

    try {
      const response = await authFetch(
        "http://16.171.39.9:5000/api/get-explanation",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }
      );

      const data = await response.json();
      setSelectedExplanation(data.explanation || "No explanation stored.");
    } catch (error) {
      setSelectedExplanation("Error loading explanation.");
    }

    setLoadingExplanation(false);
  };

  const getSeverityClass = (severity) => {
    switch (severity) {
      case "critical": return "danger";
      case "high": return "warning";
      case "medium": return "info";
      case "low": return "success";
      default: return "secondary";
    }
  };

  const getAttackTypeClass = (type) => {
    switch (type) {
      case "sql_injection":
      case "command_injection":
      case "xxe":
      case "webshell_upload":
        return "danger";
      case "ssrf":
      case "lfi_rfi":
        return "warning";
      case "directory_traversal":
      case "xss":
        return "info";
      case "bruteforce_attempt":
      case "http_parameter_pollution":
        return "secondary";
      case "typosquatting":
        return "primary";
      default:
        return "secondary";
    }
  };

  return (
    <div className="attacks-container">

      {/* Header */}
      <div className="attacks-header">
        <h2>
          <i className="fas fa-list header-icon"></i>
          Attack Detection Results
        </h2>
        <p>View and filter all detected security threats</p>
      </div>

      {/* 🔥 Filter Section Restored */}
      <div className="attacks-card filter-card">
        <div className="filter-header">
          <h5 className="filter-title">
            <i className="fas fa-search filter-icon"></i>
            FILTER RESULTS
          </h5>

          <div className="filter-controls">
            <select
              className="filter-select"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              <option value="">All Attack Types</option>

              {[...new Set(attacks.map(a => a.attack_type))]
                .filter(Boolean)
                .map((type) => (
                  <option key={type} value={type}>
                    {type.replace(/_/g, " ").toUpperCase()}
                  </option>
              ))}
            </select>

            <a href="/export" className="export-button">
              <i className="fas fa-download"></i> Export
            </a>
          </div>
        </div>
      </div>

      {/* Table Section */}
      <div className="attacks-card">
        {loading ? (
          <div className="loading-state">Loading...</div>
        ) : filteredAttacks.length > 0 ? (
          <div className="table-wrapper">
            <table className="attacks-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>URL</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {filteredAttacks.map((attack, index) => (
                  <tr key={index}>
                    <td>
                      {attack.timestamp?.substring(0, 19).replace("T", " ")}
                    </td>

                    <td>
                      <code>{attack.source_ip}</code>
                    </td>

                    <td>
                      <span
                        className={`badge ${getAttackTypeClass(attack.attack_type)}`}
                      >
                        {attack.attack_type?.replace(/_/g, " ").toUpperCase()}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`badge ${getSeverityClass(attack.severity)}`}
                      >
                        {attack.severity?.toUpperCase()}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`badge ${
                          attack.is_malicious ? "danger" : "success"
                        }`}
                      >
                        {attack.is_malicious ? "Malicious" : "Safe"}
                      </span>
                    </td>

                    <td className="url-cell" title={attack.url}>
                      {attack.url.length > 60
                        ? attack.url.substring(0, 60) + "..."
                        : attack.url}
                    </td>

                    <td>
                      <button
                        className="explain-btn"
                        onClick={() => fetchExplanation(attack.url)}
                      >
                        {loadingExplanation ? "Loading..." : "View"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <i className="fas fa-shield-alt"></i>
            <h5>No attack data found</h5>
            <p>Generate sample data to see results here</p>
          </div>
        )}
      </div>

      {/* Modal Popup */}
      {selectedExplanation && (
        <div className="ai-modal-overlay">
          <div className="ai-modal">
            <h4>🤖 AI Explanation</h4>
            <p style={{ whiteSpace: "pre-wrap" }}>
              {selectedExplanation}
            </p>
            <button
              className="close-modal-btn"
              onClick={() => setSelectedExplanation(null)}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Attacks;