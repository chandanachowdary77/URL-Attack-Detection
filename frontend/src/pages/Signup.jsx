import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import "../index.css";
import { auth } from "../firebase";
import { createUserWithEmailAndPassword, sendEmailVerification, updateProfile } from "firebase/auth";
import { FaEye, FaEyeSlash } from "react-icons/fa";

function Signup() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    try {
      const userCred = await createUserWithEmailAndPassword(auth, email, password);
      // set display name (username)
      try { await updateProfile(userCred.user, { displayName: username }); } catch {}

      // send verification email
      let sent = false;
      try {
        await sendEmailVerification(userCred.user);
        sent = true;
        alert("Verification email sent. Please check your inbox (and spam folder).");
      } catch (emailErr) {
        console.error("verification email error", emailErr);
        alert("Account created but failed to send verification email. " +
              "Make sure you have enabled Email/Password auth in Firebase and " +
              "added your domain to the authorized domains list.");
      }

      // if create succeeded and we didn't send an email, fetch a link from backend
      if (!sent) {
        try {
          const token = await userCred.user.getIdToken();
          const resp = await fetch("/api/gen-verify-link", {
            method: "POST",
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          });
          const j = await resp.json();
          if (j.link) {
            console.log("verification link:", j.link);
            alert("Verification link generated (see console). You can open it manually.");
          }
        } catch (err) {
          console.error("backend verify-link error", err);
        }
      }

      // navigate to verification page (pass email for convenience)
      navigate("/verify-otp", { state: { email } });
    } catch (error) {
      console.error(error);
      alert(error.message || "Signup failed");
    }
  };

  return (
    <div className="signup-wrapper">
      <div className="signup-card">
        <h2>Create Account</h2>
        <p className="subtitle">Join URLGuard AI securely</p>

        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />

          <input
            type="email"
            placeholder="Email Address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <div className="password-wrapper">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <span
              className="toggle-icon"
              onClick={() => setShowPassword((prev) => !prev)}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <FaEyeSlash /> : <FaEye />}
            </span>
          </div>

          <div className="password-wrapper">
            <input
              type={showConfirmPassword ? "text" : "password"}
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
            <span
              className="toggle-icon"
              onClick={() => setShowConfirmPassword((prev) => !prev)}
              aria-label={showConfirmPassword ? "Hide password" : "Show password"}
            >
              {showConfirmPassword ? <FaEyeSlash /> : <FaEye />}
            </span>
          </div>

          <button type="submit">Sign Up</button>
        </form>

        <div className="login-link">
          Already have an account? <Link to="/login">Login</Link>
        </div>
      </div>
    </div>
  );
}

export default Signup;