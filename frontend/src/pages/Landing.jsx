import React from "react";
import { Link } from "react-router-dom";
import "../index.css";

const Landing = () => {
  return (
    <div className="landing-page">

      {/* NAVBAR */}
      <header className="header">
        <nav className="navbar">
          <div className="logo">
            🛡️ URLGuard <span>AI</span>
          </div>

          <ul className="nav-links">
            <li><a href="#home">Home</a></li>
            <li><a href="#about">About</a></li>
            <li><a href="#modules">Modules</a></li>
            <li><a href="#workflow">Workflow</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>

          <div className="auth-buttons">
            <Link className="btn btn-outline" to="/login">
              Login
            </Link>
            <Link className="btn btn-primary" to="/signup">
              Get Started
            </Link>
          </div>
        </nav>

        {/* HERO */}
        <section className="hero" id="home">
          <div className="hero-inner">

            <div className="hero-content">
              <p className="eyebrow">
                AI-Powered URL Attack Intelligence
              </p>

              <h1>
                Detect, classify, and investigate URL-based cyber
                attacks in real time.
              </h1>

              <p>
                Build a complete security workflow for typosquatting,
                SQL injection, XSS, SSRF, command injection,
                LFI/RFI, brute-force patterns, and more.
              </p>

              <div className="hero-cta">
                <Link className="btn btn-primary" to="/login">
                  Open Dashboard
                </Link>
                <a className="btn btn-ghost" href="#modules">
                  View Modules
                </a>
              </div>

              <div className="hero-card">
                <h3>Live Detection Coverage</h3>
                <ul>
                  <li>Typosquatting / URL Spoofing</li>
                  <li>SQL Injection & XSS Variants</li>
                  <li>Directory Traversal & SSRF</li>
                  <li>LFI / RFI & Command Injection</li>
                  <li>HTTP Parameter Pollution & XXE</li>
                </ul>
              </div>
            </div>

            <div className="hero-image">
              <img src="/images/hero-img.jpg" alt="Hero" />
            </div>

          </div>
        </section>
      </header>

      {/* MAIN */}
      <main>

        <section className="section" id="about">
          <div className="section-inner">
            <h2>About URLGuard AI</h2>
            <p>
              URLGuard AI ingests HTTP telemetry, detects malicious
              URL patterns, classifies attack attempts, and provides
              visualization tools for security teams.
            </p>
          </div>
        </section>

        <section className="section" id="modules">
          <div className="section-inner">
            <h2>Required Modules</h2>

            <div className="grid cards-3">
              <div className="card">
                <h3>Data Ingestion</h3>
                <p>Import PCAP and URL logs from multiple sources.</p>
              </div>

              <div className="card">
                <h3>Detection Engine</h3>
                <p>Detect advanced URL-based attack patterns.</p>
              </div>

              <div className="card">
                <h3>Threat Visualization</h3>
                <p>Interactive dashboards for attack insights.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="section" id="workflow">
          <div className="section-inner">
            <h2>Workflow</h2>

            <div className="timeline">
              <div><strong>1.</strong> Generate simulated attacks.</div>
              <div><strong>2.</strong> Ingest traffic data.</div>
              <div><strong>3.</strong> Detect malicious patterns.</div>
              <div><strong>4.</strong> Classify attempts vs success.</div>
              <div><strong>5.</strong> Export investigation reports.</div>
            </div>
          </div>
        </section>

      </main>

      {/* FOOTER */}
      <footer className="footer" id="contact">
        <div className="footer-inner">
          <p>
            © 2026 URLGuard AI. Secure HTTP ecosystems through intelligent URL threat analysis.
          </p>
        </div>
      </footer>

    </div>
  );
};

export default Landing;