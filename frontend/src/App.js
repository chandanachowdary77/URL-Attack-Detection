import { BrowserRouter, Routes, Route } from "react-router-dom";

import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import OTPVerification from "./pages/OTPVerification";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";

import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Analyze from "./pages/Analyze";
import Attacks from "./pages/Attacks";
import Export from "./pages/Export";
import Pcap from "./pages/Pcap";

function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* Public Pages */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/verify-otp" element={<OTPVerification />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Protected App Pages */}
        <Route path="/" element={<Layout />}>
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="analyze" element={<Analyze />} />
          <Route path="attacks" element={<Attacks />} />
          <Route path="export" element={<Export />} />
          <Route path="pcap" element={<Pcap />} />

         </Route>

      </Routes>
    </BrowserRouter>
  );
}

export default App;