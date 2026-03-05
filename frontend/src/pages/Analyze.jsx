import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { authFetch } from "../api";
import "./Analyze.css";

const Analyze = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [explanation, setExplanation] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  // ✅ Smart Time Formatter
  const formatTime = (date) => {
    if (!date) return "Recently";

    const parsedDate = new Date(date);
    if (isNaN(parsedDate.getTime())) return "Recently";

    const diffSeconds = Math.floor(
      (Date.now() - parsedDate.getTime()) / 1000
    );

    let relative = "";

    if (diffSeconds < 60) {
      relative = "Just now";
    } else if (diffSeconds < 3600) {
      relative = `${Math.floor(diffSeconds / 60)} minutes ago`;
    } else if (diffSeconds < 86400) {
      relative = `${Math.floor(diffSeconds / 3600)} hours ago`;
    } else {
      relative = `${Math.floor(diffSeconds / 86400)} days ago`;
    }

    const exactDate = parsedDate.toLocaleString("en-IN", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });

    return `${relative} (${exactDate})`;
  };

  const analyzeURL = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setResult(null);
    setExplanation("");

    try {
      const response = await authFetch("http://localhost:5000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await response.json();
setResult(data);

// ✅ If explanation already exists in DB, show it automatically
if (data?.ai_explanation && data.ai_explanation.trim() !== "") {
  setExplanation(data.ai_explanation);
}
    } catch (error) {
      alert("Error analyzing URL");
    }

    setLoading(false);
  };

  // 🤖 AI Explain Function (UPDATED ONLY THIS PART)
  const handleExplain = async () => {

    // 🛑 Do not call AI for safe URLs
    if (!result?.is_malicious) {
      setExplanation("This URL is safe. No attack explanation required.");
      return;
    }

    setAiLoading(true);
    setExplanation("");

    try {
      const response = await authFetch("http://localhost:5000/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: result.url,
          attack_type: result.attacks_detected?.[0]?.type || "unknown"
        })
      });

      const data = await response.json();

      if (data?.explanation && data.explanation.trim() !== "") {
        setExplanation(data.explanation);
      } else {
        setExplanation("AI did not return any explanation.");
      }

    } catch (error) {
      setExplanation("Error getting AI explanation.");
    } finally {
      // 🔥 Always stop loading
      setAiLoading(false);
    }
  };

  return (
    <div className="analyze-container">

      {/* 🔹 Analyze Form */}
      <div className="analyze-card">
        <h4 className="analyze-title">
          <i className="fas fa-search analyze-icon"></i>
          URL Security Analysis
        </h4>

        <form onSubmit={analyzeURL}>
          <label className="analyze-label">
            Enter URL to analyze:
          </label>

          <input
            type="text"
            className="analyze-input"
            placeholder="https://example.com/path?param=value"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />

          <small className="analyze-help">
            Detect SQL injection, XSS, directory traversal and more.
          </small>

          <button
            type="submit"
            className="analyze-button"
            disabled={loading}
          >
            {loading ? "Analyzing..." : "Analyze URL"}
          </button>
        </form>
      </div>

      {/* 🔹 Results */}
      {result && (
        <div className="result-card">

          {/* ✅ DUPLICATE CASE */}
          {result.already_analyzed ? (
            <div className="alert alert-info">
              <strong>This URL was already analyzed.</strong>

              <div className="mt-1 text-muted">
                Last analyzed {formatTime(result.last_analyzed)}
              </div>

              <div className="mt-2">
                <button
                  className="results-btn"
                  onClick={() => navigate("/attacks")}
                >
                  Check Results Page
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* 🔹 HEADER */}
              <div className="result-header">
                <h4 className="analyze-title">
                  <i className="fas fa-chart-line analyze-icon"></i>
                  Analysis Results
                </h4>

                <span
                  className={`result-badge ${
                    result.is_malicious ? "danger" : "success"
                  }`}
                >
                  {result.is_malicious ? "MALICIOUS" : "SAFE"}
                </span>
              </div>

              {/* 🔹 URL */}
              <div className="url-box">
                <code>{result.url}</code>
              </div>

              {/* 🔹 MALICIOUS RESULT */}
              {result.is_malicious ? (
                <>
                  {/* Risk Score */}
                  <div className="mb-4">
                    <p className="summary-label">Risk Score</p>
                    <div
                      className="progress"
                      style={{ height: "14px", borderRadius: "8px" }}
                    >
                      <div
                        className="progress-bar bg-danger"
                        style={{
                          width: `${Math.round(
                            (result.confidence || 0) * 100
                          )}%`
                        }}
                      ></div>
                    </div>
                    <div className="mt-1 fw-semibold">
                      {Math.round((result.confidence || 0) * 100)} / 100
                    </div>
                  </div>

                  {/* Summary Grid */}
                  <div className="summary-grid">
                    <div>
                      <p className="summary-label">Severity</p>
                      <span className="badge warning">
                        {result.severity?.toUpperCase()}
                      </span>
                    </div>

                    <div>
                      <p className="summary-label">Confidence</p>
                      <strong>
                        {(result.confidence * 100).toFixed(1)}%
                      </strong>
                    </div>

                    <div>
                      <p className="summary-label">Threats</p>
                      <strong>
                        {result.attacks_detected?.length}
                      </strong>
                    </div>
                  </div>

                  {/* Attack Table */}
                  {result.attacks_detected?.length > 0 && (
                    <>
                      <table className="threat-table">
                        <thead>
                          <tr>
                            <th>Attack Type</th>
                            <th>Pattern</th>
                            <th>Confidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.attacks_detected.map((attack, index) => (
                            <tr key={index}>
                              <td>
                                <span className="badge danger">
                                  {attack.type
                                    .replace(/_/g, " ")
                                    .toUpperCase()}
                                </span>
                              </td>
                              <td>
                                <code>{attack.pattern_matched}</code>
                              </td>
                              <td>
                                {(attack.confidence * 100).toFixed(1)}%
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>

                      {/* 🤖 AI Explain Button */}
                      <div className="mt-3">
                        <button
                          className="analyze-button"
                          onClick={handleExplain}
                          disabled={aiLoading}
                        >
                          {aiLoading
                            ? "Generating AI Explanation..."
                            : "🤖 Explain with AI"}
                        </button>
                      </div>

                      {/* 🔹 AI Explanation */}
                      {explanation && (
                        <div className="ai-explanation mt-3">
                          <h6>AI Explanation</h6>
                          <p style={{ whiteSpace: "pre-wrap" }}>
                            {explanation}
                          </p>
                        </div>
                      )}
                    </>
                  )}
                </>
              ) : (
                <div className="safe-alert">
                  No malicious patterns detected. Continue monitoring.
                </div>
              )}
            </>
          )}

        </div>
      )}
    </div>
  );
};

export default Analyze;