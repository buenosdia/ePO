import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default function Scripts() {
  const { claims } = useAuth();
  const [scripts, setScripts] = useState<any[]>([]);
  const [name, setName] = useState('');
  const [content, setContent] = useState('');
  const [visibility, setVisibility] = useState<'private' | 'tenant'>('private');
  const [status, setStatus] = useState<string | null>(null);

  async function load() {
    const { data } = await api.get('/epo.scripts?select=id,name,visibility,created_at');
    setScripts(data);
  }

  useEffect(() => { void load(); }, []);

  async function createScript() {
    if (!claims) return;
    try {
      setStatus(null);
      const scriptRes = await api.post('/epo.scripts', {
        tenant_id: claims.tenant_id,
        name,
        visibility,
        created_by: claims.sub
      });
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(content));
      const hex = bytesToHex(new Uint8Array(hashBuffer));
      await api.post('/epo.script_versions', {
        script_id: scriptRes.data.id,
        version: 1,
        content,
        content_sha256: `\\x${hex}`,
        is_signed: false,
        released_by: claims.sub
      });
      setName('');
      setContent('');
      await load();
      setStatus('Script created');
    } catch (err) {
      console.error(err);
      setStatus('Create failed');
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Scripts</h2>
      <section>
        <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={visibility} onChange={(e) => setVisibility(e.target.value as any)}>
          <option value="private">Private</option>
          <option value="tenant">Tenant</option>
        </select>
        <textarea
          placeholder="PowerShell content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={10}
          cols={80}
        />
        <div>
          <button onClick={createScript} disabled={!name || !content}>Create Script + Version</button>
        </div>
        {status && <p>{status}</p>}
      </section>
      <hr />
      <ul>
        {scripts.map((s) => (
          <li key={s.id}>{s.name} ({s.visibility})</li>
        ))}
      </ul>
    </div>
  );
}
