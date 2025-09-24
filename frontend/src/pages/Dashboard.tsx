import React from 'react';
import { useAuth } from '../context/AuthContext';

export default function Dashboard() {
  const { claims, logout } = useAuth();
  return (
    <div style={{ padding: 24 }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Enterprise PowerShell Orchestrator</h2>
          <p>Tenant: {claims?.tenant_slug}</p>
        </div>
        <button onClick={logout}>Sign Out</button>
      </header>
      <section>
        <h3>Overview</h3>
        <ul>
          <li>Queued jobs</li>
          <li>Recent failures</li>
          <li>Agent health</li>
        </ul>
      </section>
    </div>
  );
}
