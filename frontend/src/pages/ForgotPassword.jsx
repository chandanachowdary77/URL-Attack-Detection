import { useState } from "react";
import { Link } from "react-router-dom";
import { auth } from "../firebase";
import { sendPasswordResetEmail } from "firebase/auth";
import "../index.css";

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setSending(true);
      await sendPasswordResetEmail(auth, email);
      setMessage("Password reset email sent successfully. Check your inbox.");
      setEmail("");
    } catch (error) {
      console.error(error);
      setMessage(error.message || "Failed to send reset email");
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <h2>Reset Password</h2>
        <p className="subtitle">Enter your email to receive a reset link.</p>
        {message && (
          <div style={{
            marginTop: 12,
            padding: 10,
            borderRadius: 4,
            backgroundColor: message.includes("successfully") ? "#d4edda" : "#f8d7da",
            color: message.includes("successfully") ? "#155724" : "#721c24"
          }}>
            {message}
          </div>
        )}
        <form onSubmit={handleSubmit}>
          <input
            type="email"
            placeholder="Email Address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <button type="submit" disabled={sending}>Send Reset Email</button>
        </form>
        <div className="login-link">
          <Link to="/login">Back to Login</Link>
        </div>
      </div>
    </div>
  );
}

export default ForgotPassword;
