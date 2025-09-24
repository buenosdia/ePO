import React, { useState } from 'react';
import { loginLocal, loginLdap } from '../lib/api';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState<'local' | 'ldap'>('local');
  const [tenant, setTenant] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setStatus(null);
    try {
      const fn = mode === 'local' ? loginLocal : loginLdap;
      const { token } = await fn(tenant, username, password);
      if (!token) throw new Error('No token returned');
      login(token);
      window.location.href = '/';
    } catch (err) {
      console.error(err);
      setStatus('Authentication failed');
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: '10% auto', fontFamily: 'Inter, system-ui' }}>
      <h1>EPO Login</h1>
      <div style={{ marginBottom: 12 }}>
        <button type="button" onClick={() => setMode('local')} disabled={mode === 'local'}>Local</button>
        <button type="button" onClick={() => setMode('ldap')} disabled={mode === 'ldap'}>LDAP</button>
      </div>
      <form onSubmit={submit}>
        <input placeholder="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} required />
        <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <div style={{ marginTop: 12 }}>
          <button type="submit">Sign In</button>
        </div>
      </form>
      {status && <p style={{ color: 'crimson' }}>{status}</p>}
    </div>
  );
}
