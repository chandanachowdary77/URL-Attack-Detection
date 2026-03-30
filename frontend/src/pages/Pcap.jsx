import React, { useState, useEffect } from "react";
import { authFetch } from "../api";
import { auth } from "../firebase";
import "./Pcap.css";

const Pcap = () => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [files, setFiles] = useState([]);

  useEffect(() => {
    fetchUploadedFiles();
  }, []);

  const fetchUploadedFiles = async () => {
    try {
      const res = await authFetch("http://localhost:5000/api/pcap-files");
      const data = await res.json();
      setFiles(data.files || []);
    } catch (err) {
      console.error("Failed to load files");
    }
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a PCAP file");
      return;
    }

    setLoading(true);
    setSummary(null);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      // include auth token
      const user = auth.currentUser;
      const headers = {};
      if (user) {
        const token = await user.getIdToken();
        headers["Authorization"] = `Bearer ${token}`;
      }
      const response = await fetch(
        "http://localhost:5000/api/upload-pcap",
        {
          method: "POST",
          headers,
          body: formData
        }
      );

      const data = await response.json();

      if (response.ok) {
        setSummary(data);
        fetchUploadedFiles();
      } else {
        setError(data.error || "Processing failed");
      }

    } catch (err) {
      console.error(err);
      setError("Upload failed");
    }

    setLoading(false);
  };

  const breakdown = summary?.attack_breakdown || {};

  return (
    <div className="pcap-wrapper">

      {/* Upload Section */}
      <div className="pcap-upload-card">

        <div
          className="upload-area"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const droppedFile = e.dataTransfer.files[0];
            if (droppedFile) setFile(droppedFile);
          }}
        >
          <i className="fas fa-cloud-upload-alt upload-icon"></i>

          <h4>Drop PCAP file here or click to browse</h4>
          <p>Upload network capture files for automated threat analysis</p>

          <label className="select-btn">
            Select File
            <input
              type="file"
              accept=".pcap,.pcapng,.txt"
              onChange={(e) => setFile(e.target.files[0])}
              hidden
            />
          </label>

          {file && (
            <div className="selected-file">
              {file.name}
            </div>
          )}
        </div>

        <button
          className="analyze-btn"
          onClick={handleUpload}
          disabled={loading}
        >
          {loading ? "Processing..." : "Analyze PCAP"}
        </button>

        {error && (
          <div className="alert alert-danger mt-3">
            {error}
          </div>
        )}
      </div>

      {/* Latest Analysis Summary */}
      {summary && (
        <div className="pcap-results-row">

          {/* LEFT → SUMMARY */}
          <div className="pcap-summary-card">
            <h4>
              <i className="fas fa-chart-bar"></i> Latest Analysis Summary
            </h4>

            <p><strong>Filename:</strong> {summary.filename || "N/A"}</p>
            <p><strong>File Size:</strong> {summary.file_size_mb ?? 0} MB</p>
            <p><strong>Total URLs:</strong> {summary.total_urls ?? 0}</p>
            <p><strong>New Attacks Found:</strong> {summary.malicious_detected ?? 0}</p>
            <p><strong>Processing Time:</strong> {summary.processing_time_sec ?? 0} sec</p>

            <a
              href={`http://16.171.39.9:5000/api/export-pcap-file?file=${summary.filename}`}
              className="btn btn-outline-primary export-btn"
            >
              <i className="fas fa-download"></i> Export This PCAP Attacks (CSV)
            </a>
          </div>

          {/* RIGHT → DETECTED THREATS */}
          <div className="pcap-threat-card">
            <h4>
              <i className="fas fa-bug"></i> Detected Threats
            </h4>

            {Object.keys(breakdown).length === 0 ? (
              <p>No attacks detected</p>
            ) : (
              <div className="threat-list">
                {Object.entries(breakdown).map(([type, count]) => (
                  <div key={type} className="threat-item">
                    <span>
                      {type.replace(/_/g, " ").toUpperCase()}
                    </span>
                    <span className="threat-count">
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>
      )}

      {/* Uploaded Files History Table */}
      <div className="pcap-uploaded-section">
        <h4>
          <i className="fas fa-folder-open"></i> Uploaded PCAP Files
        </h4>

        {files.length === 0 ? (
          <p className="text-muted">No files uploaded yet.</p>
        ) : (
          <div className="table-responsive">
            <table className="pcap-history-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Size (MB)</th>
                  <th>URLs</th>
                  <th>Attacks</th>
                  <th>Upload Time</th>
                  <th>Processing</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {files.map((fileItem) => (
                  <tr key={fileItem.filename}>
                    <td>{fileItem.filename}</td>
                    <td>{fileItem.size_mb}</td>
                    <td>{fileItem.total_urls}</td>
                    <td className="attack-count">
                      {fileItem.attacks_found}
                    </td>
                    <td>{fileItem.upload_time}</td>
                    <td>{fileItem.processing_time}</td>
                    <td>
                      <span className="status-badge">
                        {fileItem.status}
                      </span>
                    </td>
                    <td>
                      <a
                        href={`http://localhost:5000/api/export-pcap-file?file=${fileItem.filename}`}
                        className="btn btn-sm btn-primary"
                      >
                        Export
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>

            </table>
          </div>
        )}
      </div>

    </div>
  );
};

export default Pcap;