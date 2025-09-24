import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';

export default function Jobs() {
  const { claims } = useAuth();
  const [jobs, setJobs] = useState<any[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [status, setStatus] = useState<string | null>(null);

  async function load() {
    const { data } = await api.get('/epo.jobs?select=id,name,status');
    setJobs(data);
  }

  useEffect(() => { void load(); }, []);

  async function enqueue() {
    if (!selected) return;
    try {
      setStatus(null);
      await api.post('/rpc/sp_enqueue_job', { p_job_id: selected, p_trigger: 'manual' });
      setStatus('Run queued');
    } catch (err) {
      console.error(err);
      setStatus('Queue failed');
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Jobs</h2>
      <select value={selected} onChange={(e) => setSelected(e.target.value)}>
        <option value="">-- select job --</option>
        {jobs.map((job) => (
          <option key={job.id} value={job.id}>{job.name} ({job.status})</option>
        ))}
      </select>
      <button onClick={enqueue} disabled={!selected || !claims}>Run Now</button>
      {status && <p>{status}</p>}
    </div>
  );
}
