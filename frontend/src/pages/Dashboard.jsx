import React, { useEffect, useState } from "react";
import { authFetch } from "../api";
import "./Dashboard.css";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend
} from "chart.js";
import ChartDataLabels from "chartjs-plugin-datalabels";

import { Pie } from "react-chartjs-2";

ChartJS.register(ArcElement, Tooltip, Legend, ChartDataLabels);

const Dashboard = () => {
  const [stats, setStats] = useState({
  total_attacks: 0,
  malicious_attacks: 0,
  successful_attacks: 0,
  attack_types: {},
  severity_distribution: {}
});
  const [recentAttacks, setRecentAttacks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
  try {
    const statsRes = await authFetch("http://16.171.39.9:5000/api/statistics");
    const statsData = await statsRes.json();
    console.log("Stats:", statsData);
    setStats(statsData);

    const attacksRes = await authFetch("http://16.171.39.9:5000/api/history");
    const attacksData = await attacksRes.json();
    console.log("Attacks:", attacksData);

    // 🔥 REMOVE DUPLICATE URLs BEFORE DISPLAYING
    if (attacksData.attacks) {
      const uniqueMap = new Map();

      attacksData.attacks.forEach((attack) => {
        if (!uniqueMap.has(attack.url)) {
          uniqueMap.set(attack.url, attack);
        }
      });

      const uniqueAttacks = Array.from(uniqueMap.values());

      setRecentAttacks(uniqueAttacks.slice(0, 5));
    } else {
      setRecentAttacks([]);
    }

  } catch (error) {
    console.error("Error loading dashboard:", error);
  }
  setLoading(false);
};

  const generateSampleData = async () => {
    if (!window.confirm("Generate 100 sample attack records?")) return;

    try {
      const response = await authFetch(
        "http://16.171.39.9:5000/api/generate-dataset",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ num_records: 100 })
        }
      );

      const data = await response.json();

      if (data.success) {
        alert(`Generated ${data.records_generated} records`);
        loadDashboard();
      }
    } catch (error) {
      alert("Error generating data");
    }
  };

  if (loading) return <div className="text-center mt-5">Loading...</div>;

const maliciousRate = stats?.malicious_rate || 0;
  

  return (
    <div className="dashboard-container">

      <div className="mb-4 dashboard-title">
  <h2 className="fw-bold">
    <i className="fas fa-chart-line me-2 dashboard-icon"></i> Security Dashboard
  </h2>
  <p>
    Monitor your URL security threats in real time
  </p>
</div>
      {/* Stats Cards */}
      <div className="row g-4 mb-4">
        <StatCard
          title="Total Attacks"
          value={stats?.total_attacks || 0}
          icon="fas fa-bug"
        />
        <StatCard
          title="Successful Attacks"
          value={stats?.successful_attacks || 0}
          icon="fas fa-fire"
        />
        <StatCard
          title="Attack Types"
          value={stats.attack_types ? Object.keys(stats.attack_types).length : 0}
          icon="fas fa-layer-group"
        />
        <StatCard
          title="Malicious Rate"
          value={`${maliciousRate}%`}
          icon="fas fa-percent"
        />
      </div>

<div className="row mb-4">

  {/* LEFT → Attack Type Distribution */}
  <div className="col-lg-6 mb-4">
    <div className="card p-4 shadow-sm h-100">
      <h5 className="mb-3">
        <i className="fas fa-chart-pie me-2"></i>
        Attack Types Distribution
      </h5>

      {stats?.attack_types &&
      Object.keys(stats.attack_types).length > 0 ? (
        <div style={{ Height: "450px" }}>
          <Pie
  data={{
    labels: Object.keys(stats.attack_types).map(type =>
      type.replace(/_/g, " ").toUpperCase()
    ),
    datasets: [
      {
        data: Object.values(stats.attack_types),
        backgroundColor: [
          "#6c63ff",
          "#00c6ff",
          "#ff6584",
          "#ffc107",
          "#20c997",
          "#dc3545"
        ],
        borderWidth: 1
      }
    ]
  }}
  options={{
    responsive: true,
    layout: {
  padding: {
    top: 60,
    bottom: 60,
    left: 80,
    right: 80
  }
},
    plugins: {
      legend: {
        display: false
      },
      tooltip: {
        callbacks: {
          label: function (context) {
            return `${context.label}: ${context.raw} attacks`;
          }
        }
      },
      datalabels: {
        color: "#000000",
        formatter: (value, context) => {
          const data = context.chart.data.datasets[0].data;
          const total = data.reduce((a, b) => a + b, 0);
          const percentage = ((value / total) * 100).toFixed(0);
          return `${context.chart.data.labels[context.dataIndex]} ${percentage}%`;
        },
        anchor: "end",
        align: "end",
        offset: 20,
        clamp: true,
        clip: false,
        font: {
          weight: "bold",
          size: 12
        }
      }
    }
  }}
/>
        </div>
      ) : (
        <p className="text-muted text-center">
          No attack data available
        </p>
      )}
    </div>
  </div>

  {/* RIGHT → Severity Distribution */}
  <div className="col-lg-6 mb-4">
    <div className="card p-4 shadow-sm h-100">
      <h5 className="mb-3">
        <i className="fas fa-exclamation-triangle me-2"></i>
        Severity Distribution
      </h5>

      {stats?.severity_distribution &&
      Object.keys(stats.severity_distribution).length > 0 ? (
        Object.entries(stats.severity_distribution).map(([severity, count]) => {

          const total = Object.values(stats.severity_distribution)
            .reduce((a, b) => a + b, 0);

          const percentage = ((count / total) * 100).toFixed(1);

          const severityColors = {
            critical: "bg-danger",
            high: "bg-warning",
            medium: "bg-info",
            low: "bg-success"
          };

          return (
            <div key={severity} className="mb-3">
              <div className="d-flex justify-content-between">
                <span className="text-capitalize fw-semibold">
                  {severity}
                </span>
                <span>{count} ({percentage}%)</span>
              </div>

              <div className="progress" style={{ height: "15px", borderRadius: "8px" }}>
                <div
                  className={`progress-bar ${severityColors[severity] || "bg-secondary"}`}
                  style={{ width: `${percentage}%` }}
                ></div>
              </div>
            </div>
          );
        })
      ) : (
        <p className="text-muted text-center">
          No severity data available
        </p>
      )}
    </div>
  </div>

</div>
{/* Recent Attacks */}
<div className="card p-4 shadow-sm">
  <h5 className="mb-3">
    <i className="fas fa-history me-2"></i>
    Recent Attacks
  </h5>

  {recentAttacks.length > 0 ? (
    <div className="table-responsive">
      <table className="table table-bordered table-hover">
        <thead className="table-light">
          <tr>
            <th>Time</th>
            <th>Attack Type</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>URL</th>
          </tr>
        </thead>

        <tbody>
          {recentAttacks.map((attack, index) => {

            const severityRowClass = {
              critical: "table-danger",
              high: "table-warning",
              medium: "table-info",
              low: "table-success"
            };

            const severityBadgeColor =
              attack.severity === "critical"
                ? "danger"
                : attack.severity === "high"
                ? "warning"
                : attack.severity === "medium"
                ? "info"
                : "success";

            const confidencePercent = Math.round(
              (attack.confidence || 0) * 100
            );

            return (
              <tr
                key={attack.id || index}
                className={severityRowClass[attack.severity] || ""}
              >

                {/* Time */}
                <td>
                  {attack.timestamp
                    ?.substring(0, 19)
                    .replace("T", " ")}
                </td>

                {/* Attack Type */}
                <td>
                  {attack.attack_type
                    ?.replace(/_/g, " ")
                    .toUpperCase()}
                </td>

                {/* Severity */}
                <td>
                  <span className={`badge bg-${severityBadgeColor}`}>
                    {attack.severity?.toUpperCase()}
                  </span>
                </td>

                {/* Confidence */}
                <td>
                  {confidencePercent}%
                </td>

                {/* URL */}
                <td style={{ maxWidth: "250px" }}>
                  <div
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap"
                    }}
                    title={attack.url}
                  >
                    {attack.url}
                  </div>
                </td>

              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  ) : (
    <div className="text-center py-4">
      <h6 className="text-muted">
        No attacks recorded yet
      </h6>
      <button
        className="btn btn-primary mt-3"
        onClick={generateSampleData}
      >
        Generate Sample Data
      </button>
    </div>
  )}
</div>

    </div>
  );
};

const StatCard = ({ title, value, icon }) => (
  <div className="col-md-3">
    <div className="stat-card">
      <div className="stat-content">
        <div>
          <h3>{value}</h3>
          <p>{title}</p>
        </div>
        <div className="stat-icon">
          <i className={icon}></i>
        </div>
      </div>
    </div>
  </div>
);

export default Dashboard;