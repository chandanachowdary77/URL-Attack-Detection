import React, { useState, useEffect, useRef } from "react";
import "./Layout.css";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { auth } from "../firebase";

const Layout = () => {
  const navigate = useNavigate();
  const [showMenu, setShowMenu] = useState(false);
  const [userInfo, setUserInfo] = useState({ displayName: "", email: "" });
  const menuRef = useRef();

  const handleLogout = async () => {

  const confirmLogout = window.confirm("Are you sure you want to logout?");

  if (!confirmLogout) return;

  await auth.signOut();
  navigate("/login");
};

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((user) => {
      if (user) {
        setUserInfo({ displayName: user.displayName || "", email: user.email || "" });
      } else {
        setUserInfo({ displayName: "", email: "" });
      }
    });
    return unsubscribe;
  }, []);

  // close menu when clicking outside
  useEffect(() => {
    function handleClick(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setShowMenu(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  return (
    <div className="layout-wrapper">
      <div className="main-container">

        {/* HEADER */}
        <header className="header-section">

          {/* LEFT - LOGO */}
          <div className="header-title">
            <i className="fas fa-shield-alt shield-icon"></i>
            <span>URLGuard</span>
          </div>

          {/* CENTER - NAVIGATION */}
          <nav className="nav-tabs-modern">
            <NavLink to="/dashboard" className="nav-link">
              <i className="fas fa-chart-line"></i>
              <span>Dashboard</span>
            </NavLink>

            <NavLink to="/analyze" className="nav-link">
              <i className="fas fa-search"></i>
              <span>Analyze</span>
            </NavLink>

            <NavLink to="/attacks" className="nav-link">
              <i className="fas fa-list"></i>
              <span>Results</span>
            </NavLink>

            <NavLink to="/pcap" className="nav-link">
              <i className="fas fa-upload"></i>
              <span>PCAP</span>
            </NavLink>

            <NavLink to="/export" className="nav-link">
              <i className="fas fa-file-export"></i>
              <span>Export</span>
            </NavLink>
          </nav>

          {/* RIGHT - USER */}
          {/* RIGHT - USER + LOGOUT */}
<div className="header-right">

  {/* USER DROPDOWN */}
  <div className="user-menu" ref={menuRef}>
    <div
      className="user-info"
      onClick={() => setShowMenu((v) => !v)}
      style={{ cursor: "pointer" }}
    >
      <i className="fas fa-user-circle"></i>
      <span>{userInfo.displayName || "User"}</span>
    </div>

    {showMenu && (
      <div className="user-dropdown">
        <div className="user-dropdown-item">
          <strong>{userInfo.displayName || "Unknown"}</strong>
        </div>
        <div className="user-dropdown-item">
          {userInfo.email}
        </div>
      </div>
    )}
  </div>

  {/* LOGOUT ICON BUTTON (EXTREME RIGHT) */}
  <button className="logout-icon-btn" onClick={handleLogout} title="Logout">
    <i className="fas fa-sign-out-alt"></i>
  </button>

</div>
        </header>

        {/* PAGE CONTENT */}
        <main className="content-section">
          <Outlet />
        </main>

      </div>
    </div>
  );
};

export default Layout;