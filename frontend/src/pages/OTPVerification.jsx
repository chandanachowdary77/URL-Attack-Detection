import { useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import "../index.css";
import { auth } from "../firebase";
import { sendEmailVerification } from "firebase/auth";

function OTPVerification() {
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [adminLink, setAdminLink] = useState("");
  const navigate = useNavigate();
  const location = useLocation();

  // email should be passed via location.state from signup or login
  const email = location.state?.email || "";

  const resend = async () => {
    const user = auth.currentUser;
    if (!user) {
      setMessage("No active session. Please login with your email to resend verification.");
      return;
    }

    try {
      setSending(true);
      await sendEmailVerification(user);
      setMessage("Verification email resent. Check your inbox.");
    } catch (err) {
      console.error(err);
      setMessage(err.message || "Failed to send verification email");
    } finally {
      setSending(false);
    }
  };

  const checkVerified = async () => {
    const user = auth.currentUser;
    if (!user) {
      setMessage("No active session. Please login to complete verification.");
      return;
    }

    try {
      await user.reload();
      if (user.emailVerified) {
        navigate("/dashboard");
      } else {
        setMessage("Email not yet verified. Please check your inbox.");
      }
    } catch (err) {
      console.error(err);
      setMessage(err.message || "Could not verify status");
    }
  };

  const genLink = async () => {
    const user = auth.currentUser;
    if (!user) {
      setMessage("No active session");
      return;
    }
    try {
      setSending(true);
      const token = await user.getIdToken();
      const resp = await fetch("/api/gen-verify-link", {
        method: "POST",
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const j = await resp.json();
      if (j.link) {
        setMessage("Admin-generated link below (copy/open manually):");
        setAdminLink(j.link);
      } else {
        setMessage(j.error || "could not generate link");
      }
    } catch (err) {
      console.error(err);
      setMessage("failed to contact server");
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="otp-wrapper">
      <div className="otp-card">
        <h2>Verify Your Account</h2>
        <p className="subtitle">We sent a verification email to <strong>{email || "your email"}</strong>.</p>
        {message && <div className="error">{message}</div>}
        {adminLink && (
          <div className="admin-link">
            <input type="text" readOnly value={adminLink} style={{ width: '100%' }} />
          </div>
        )}

        <button onClick={checkVerified}>I've Verified — Check Status</button>
        <div style={{ height: 8 }} />
        <button onClick={resend} disabled={sending}>{sending ? "Sending…" : "Resend verification email"}</button>
        <div style={{ height: 8 }} />
        <button onClick={genLink} disabled={sending}>{sending ? "Working…" : "Generate link (dev only)"}</button>

        <div className="login-link" style={{ marginTop: 16 }}>
          Need to login? <Link to="/login">Login</Link>
        </div>
      </div>
    </div>
  );
}

export default OTPVerification;
