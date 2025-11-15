// src/components/Login.js
import React from "react";

export default function Login() {
  const handleLogin = () => {
    window.location.href = "/auth/github"; 
  };

  return (
    <div className="login">
      <h2>Sign in with GitHub</h2>
      <button onClick={handleLogin}>Continue with GitHub</button>
    </div>
  );
}
