// src/components/RepoList.js
import React, { useEffect, useState } from "react";
import api from "./api";

export default function RepoList() {
  const [repos, setRepos] = useState([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    setLoading(true);
    api.get("/api/repos")
      .then(res => setRepos(res.data))
      .catch(err => setMsg("Failed to fetch repos"))
      .finally(() => setLoading(false));
  }, []);

  const createWebhook = async (full_name) => {
    try {
      setMsg("Creating webhook...");
      const res = await api.post("/api/repos/webhook", { repo_full_name: full_name });
      setMsg(`Webhook created: ${res.data.webhook_id}`);
    } catch (e) {
      setMsg("Webhook creation failed");
    }
  };

  if (loading) return <div>Loading repos...</div>;
  if (!repos.length) return <div>No repos found (or permission missing)</div>;

  return (
    <div>
      <h3>Your repos</h3>
      <ul>
        {repos.map(r => (
          <li key={r.id}>
            <strong>{r.full_name}</strong> — {r.language}
            <button onClick={() => createWebhook(r.full_name)} style={{ marginLeft: 10 }}>
              Create webhook
            </button>
          </li>
        ))}
      </ul>
      <div>{msg}</div>
    </div>
  );
}
