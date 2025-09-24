import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { api, AUTH_URL } from '../lib/api';
import { useAuth } from '../context/AuthContext';

type AgentKey = { id: string; name: string; public_key_pem: string };

async function importAgentKey(pem: string) {
  const clean = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const buf = Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'spki',
    buf,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default function Credentials() {
  const { claims, token } = useAuth();
  const [agents, setAgents] = useState<AgentKey[]>([]);
  const [agent, setAgent] = useState<AgentKey | null>(null);
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      if (!token) return;
      const { data } = await axios.get(`${AUTH_URL}/crypto/agent-keys`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAgents(data);
    }
    void load();
  }, [token]);

  async function save() {
    if (!claims || !agent) { return; }
    try {
      const key = await importAgentKey(agent.public_key_pem);
      const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, new TextEncoder().encode(password)));
      await api.post('/epo.credentials', {
        tenant_id: claims.tenant_id,
        name,
        username,
        cipher_text: `\\x${bytesToHex(cipher)}`,
        algorithm: 'rsa-oaep-sha256',
        pubkey_fingerprint: agent.id,
        created_by: claims.sub
      });
      setStatus('Credential saved');
      setPassword('');
    } catch (err) {
      console.error(err);
      setStatus('Save failed');
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Credentials</h2>
      <div>
        <label>Encrypt for agent: </label>
        <select value={agent?.id ?? ''} onChange={(e) => setAgent(agents.find((a) => a.id === e.target.value) ?? null)}>
          <option value="">-- select agent --</option>
          {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </select>
      </div>
      <div style={{ display: 'grid', gap: 8, maxWidth: 360, marginTop: 16 }}>
        <input placeholder="Credential name" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button onClick={save} disabled={!name || !username || !password || !agent}>Save</button>
      </div>
      {status && <p>{status}</p>}
    </div>
  );
}
