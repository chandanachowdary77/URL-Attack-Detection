import { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { auth } from "../firebase";
import { confirmPasswordReset } from "firebase/auth";
import "../index.css";

function ResetPassword() {
  const location = useLocation();
  const navigate = useNavigate();
  const params = new URLSearchParams(location.search);
  const oobCode = params.get("oobCode") || "";

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!oobCode) {
      setMessage("Invalid or missing code");
    }
  }, [oobCode]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setMessage("Passwords do not match");
      return;
    }
    try {
      await confirmPasswordReset(auth, oobCode, password);
      setMessage("Password has been reset. You can now log in.");
      setTimeout(() => navigate("/login"), 3000);
    } catch (error) {
      console.error(error);
      setMessage(error.message || "Failed to reset password");
    }
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <h2>Choose New Password</h2>
        <p className="subtitle">Enter a new password below.</p>
        {message && <div className="error">{message}</div>}
        <form onSubmit={handleSubmit}>
          <input
            type="password"
            placeholder="New Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Confirm Password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
          <button type="submit">Reset Password</button>
        </form>
      </div>
    </div>
  );
}

export default ResetPassword;
