import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import "../index.css";
import { auth } from "../firebase";
import { signInWithEmailAndPassword } from "firebase/auth";
import { FaEye, FaEyeSlash } from "react-icons/fa";

function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      // Treat the username input as email for Firebase
      const email = username;
      const userCred = await signInWithEmailAndPassword(auth, email, password);
      if (userCred.user.emailVerified) {
        navigate("/dashboard");
      } else {
        navigate("/verify-otp", { state: { email } });
      }
    } catch (error) {
      console.error(error);
      alert(error.message || "Invalid credentials");
    }
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <h2>Welcome Back</h2>
        <p className="subtitle">Secure access to URLGuard AI</p>

        <form onSubmit={handleSubmit}>
          <input
            type="email"
            placeholder="Email"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
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

          <div className="forgot">
            <Link to="/forgot-password">Forgot Password?</Link>
          </div>

          <button type="submit">Login</button>
        </form>

        <div className="signup-link">
          Don’t have an account? <Link to="/signup">Sign Up</Link>
        </div>
      </div>
    </div>
  );
}

export default Login;