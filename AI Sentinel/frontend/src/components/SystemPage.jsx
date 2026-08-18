import { useEffect, useState } from 'react';
import { applyRetention, changePassword, createUser, getRole, getSystemAudit, getSystemHealth, getSystemMetrics, listUsers, updateUser } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

const AGENT_STYLES = {
  HEALTHY: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  DEGRADED: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  OFFLINE: 'bg-red-500/15 text-red-300 border-red-400/40',
};

export default function SystemPage() {
  const [health, setHealth] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [audit, setAudit] = useState([]);
  const [users, setUsers] = useState([]);
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(true);
  const [pwForm, setPwForm] = useState({ current_password: '', new_password: '' });
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'VIEWER' });

  const load = async () => {
    setLoading(true);
    try {
      const [h, m, a, u] = await Promise.all([getSystemHealth(), getSystemMetrics(), getSystemAudit(100), listUsers()]);
      setHealth(h);
      setMetrics(m);
      setAudit(a.items || []);
      setUsers(u.items || []);
    } catch (e) { /* ignore */ } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const retention = async () => {
    try {
      const r = await applyRetention();
      flash(`Retention applied — deleted ${r.deleted?.total ?? 0} rows.`);
    } catch (e) { flash(e.message); }
  };

  const doChangePassword = async () => {
    try {
      await changePassword(pwForm.current_password, pwForm.new_password);
      flash('Password changed.');
      setPwForm({ current_password: '', new_password: '' });
    } catch (e) { flash(e.message); }
  };

  const doCreateUser = async () => {
    if (newUser.username.length < 3 || newUser.password.length < 8) { flash('Username ≥ 3 chars, password ≥ 8 chars.'); return; }
    try {
      await createUser(newUser);
      flash(`User ${newUser.username} created.`);
      setNewUser({ username: '', password: '', role: 'VIEWER' });
      load();
    } catch (e) { flash(e.message); }
  };

  const toggleUserActive = async (u) => {
    try {
      await updateUser(u.id, { is_active: !u.is_active });
      load();
    } catch (e) { flash(e.message); }
  };

  if (loading) return <Layout title="System"><Loading /></Layout>;

  const cfg = metrics?.config || {};
  const storage = metrics?.storage || {};
  const ml = metrics?.ml || {};
  const pipeline = metrics?.pipeline || {};
  const latency = pipeline.latency || {};
  const agents = metrics?.agents || [];
  const telemetry = metrics?.telemetry || health?.telemetry || {};
  const wsClients = metrics?.websocket_clients || [];

  return (
    <Layout title="System & Observability">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="panel">
          <h3 className="title mb-3">Health</h3>
          {health ? (
            <div className="space-y-2 text-sm">
              <Row k="status" v={health.status} good={health.status === 'ok'} />
              <Row k="service" v={health.service} />
              <Row k="version" v={health.version} mono />
              <Row k="database" v={health.database} good={health.database === 'ok'} />
              <Row k="pipeline" v={health.pipeline_started ? 'started' : 'stopped'} good={health.pipeline_started} />
              <Row k="telemetry" v={`${telemetry.status || 'UNKNOWN'}${telemetry.age_seconds != null ? ` (${telemetry.age_seconds}s old)` : ''}`}
                good={telemetry.status === 'OK'} />
            </div>
          ) : <Empty />}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Pipeline</h3>
          <div className="space-y-2 text-sm">
            <Row k="EPS" v={pipeline.eps} />
            <Row k="processed" v={pipeline.processed} />
            <Row k="deduplicated" v={pipeline.deduplicated} />
            <Row k="queue depth" v={`${metrics?.queue?.depth ?? 0}/${metrics?.queue?.maxsize ?? '?'}`} />
            <Row k="ws clients" v={pipeline.ws_connections} />
            <Row k="detections today" v={pipeline.detections_today} />
          </div>
        </div>

        <div className="panel">
          <h3 className="title mb-3">Storage</h3>
          <div className="space-y-2 text-sm">
            <Row k="events" v={storage.events} />
            <Row k="alerts" v={storage.alerts} />
            <Row k="incidents" v={storage.incidents} />
            <Row k="rules" v={storage.detection_rules} />
            <Row k="audit logs" v={storage.audit_logs} />
            <Row k="phishing scans" v={storage.phishing_scans} />
            <Row k="response actions" v={storage.response_actions} />
            <Row k="server stats" v={storage.server_stats} />
          </div>
          <button className="btn mt-4" onClick={retention}>Apply Retention (purge old data)</button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="panel">
          <h3 className="title mb-3">Event Latency (ingest → dashboard)</h3>
          <div className="space-y-2 text-sm">
            <Row k="samples" v={latency.samples ?? 0} />
            <Row k="p50" v={latency.p50_ms != null ? `${latency.p50_ms} ms` : '—'} />
            <Row k="p95" v={latency.p95_ms != null ? `${latency.p95_ms} ms` : '—'} />
            <Row k="p99" v={latency.p99_ms != null ? `${latency.p99_ms} ms` : '—'} />
            <Row k="max" v={latency.max_ms != null ? `${latency.max_ms} ms` : '—'} />
            <Row k="SLA met" v={`${latency.sla_met_pct ?? '—'}%`} good={(latency.sla_met_pct ?? 100) >= 99} />
            <Row k="critical SLA" v={`${latency.critical_sla_met_pct ?? '—'}%`} good={(latency.critical_sla_met_pct ?? 100) >= 99} />
            <Row k="target" v={`≤ ${latency.target_event_ms ?? cfg.latency_target_event_ms} ms (event) · ≤ ${latency.target_critical_ms ?? cfg.latency_target_critical_ms} ms (critical)`} />
          </div>
          <h3 className="title mt-4 mb-2">ML Model</h3>
          <div className="space-y-2 text-sm">
            <Row k="status" v={ml.status || '—'} />
            <Row k="version" v={ml.version ?? '—'} />
            <Row k="trained samples" v={ml.trained_samples ?? '—'} />
            <Row k="model loaded" v={ml.model_loaded ? 'yes' : 'no'} />
            <Row k="drift" v={ml.drift ? `${ml.drift.level || 'n/a'} (score ${ml.drift.score ?? '—'})` : '—'} />
            <Row k="anomaly rate" v={ml.metrics?.anomaly_rate != null ? `${Math.round(ml.metrics.anomaly_rate * 100)}%` : '—'} />
            <Row k="inference p95" v={ml.inference_latency_ms?.p95 != null ? `${ml.inference_latency_ms.p95} ms` : '—'} />
          </div>
        </div>

        <div className="panel">
          <h3 className="title mb-3">Connected Agents</h3>
          {agents.length === 0 ? <Empty message="No agents have reported a heartbeat yet." /> : (
            <div className="space-y-2 max-h-64 overflow-auto">
              {agents.map((a) => (
                <div key={a.agent_id} className="rounded-lg border border-slate-800 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs">{a.agent_id}</span>
                    <span className={`rounded-full border px-2 py-0.5 text-[11px] uppercase ${AGENT_STYLES[a.status] || AGENT_STYLES.OFFLINE}`}>{a.status}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">
                    {[a.hostname, a.os, a.ip].filter(Boolean).join(' · ') || '—'}
                  </p>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    heartbeat {fmtTime(a.last_heartbeat_at)} · {a.heartbeat_age_seconds}s ago · env {a.environment || '—'}
                  </p>
                </div>
              ))}
            </div>
          )}
          <p className="mt-2 text-[11px] text-slate-500">HEALTHY ≤ {metrics ? `${metrics?.agents_degraded_after ?? 45}s` : '45s'} · DEGRADED → OFFLINE after heartbeat gap. Agents push telemetry with the shared agent key.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="panel">
          <h3 className="title mb-3">Configuration</h3>
          <div className="space-y-2 text-sm">
            <Row k="env" v={`${cfg.env} / ${cfg.environment || 'development'}`} />
            <Row k="workers" v={cfg.workers} />
            <Row k="retention days" v={cfg.retention_days} />
            <Row k="ml enabled" v={cfg.ml_enabled ? 'yes' : 'no'} />
            <Row k="threat intel" v={cfg.ti_enabled ? 'enabled' : 'disabled'} />
            <Row k="response dry-run" v={cfg.response_dry_run ? 'yes' : 'no'} />
            <Row k="demo mode" v={cfg.demo_mode ? 'yes' : 'no'} />
            <Row k="latency targets" v={`event ≤${cfg.latency_target_event_ms}ms · critical ≤${cfg.latency_target_critical_ms}ms`} />
          </div>
        </div>

        <div className="panel">
          <h3 className="title mb-3">User Management</h3>
          <div className="space-y-2 max-h-64 overflow-auto">
            {users.map((u) => (
              <div key={u.id} className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 p-2 text-sm">
                <div>
                  <p className="font-medium">{u.username} <span className="text-slate-500 text-xs">({u.role})</span></p>
                  <p className="text-[11px] text-slate-500">{u.full_name || '—'} · {u.is_active ? 'active' : 'disabled'}</p>
                </div>
                {getRole() === 'ADMIN' ? (
                  <button className={`rounded-lg border px-2 py-1 text-[11px] ${u.is_active ? 'border-slate-700 text-slate-300' : 'border-emerald-400/40 text-emerald-300'}`}
                    onClick={() => toggleUserActive(u)}>
                    {u.is_active ? 'Disable' : 'Enable'}
                  </button>
                ) : null}
              </div>
            ))}
          </div>
          {getRole() === 'ADMIN' ? (
            <div className="mt-3 grid grid-cols-2 gap-2">
              <input className="input" placeholder="username" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
              <input className="input" placeholder="password (8+)" type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
              <select className="input" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                {['VIEWER', 'SOC_ANALYST', 'SECURITY_ENGINEER', 'ADMIN'].map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
              <button className="btn" onClick={doCreateUser}>Create User</button>
            </div>
          ) : null}
          <h3 className="title mt-4 mb-2">Change My Password</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <input className="input" placeholder="current password" type="password" value={pwForm.current_password} onChange={(e) => setPwForm({ ...pwForm, current_password: e.target.value })} />
            <input className="input" placeholder="new password (8+)" type="password" value={pwForm.new_password} onChange={(e) => setPwForm({ ...pwForm, new_password: e.target.value })} />
            <button className="btn" onClick={doChangePassword}>Change</button>
          </div>
        </div>
      </div>

      <div className="panel">
        <h3 className="title mb-3">Audit Trail (recent)</h3>
        {audit.length === 0 ? <Empty message="No audit entries." /> : (
          <div className="max-h-96 overflow-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Actor</th>
                  <th className="pb-2">Action</th>
                  <th className="pb-2">Target</th>
                  <th className="pb-2">Result</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((a) => (
                  <tr key={`${a.id}-${a.ts}`} className="border-t border-slate-800">
                    <td className="py-1.5 whitespace-nowrap text-slate-500">{fmtTime(a.ts)}</td>
                    <td className="py-1.5 font-mono">{a.actor}</td>
                    <td className="py-1.5 font-mono text-accent">{a.action}</td>
                    <td className="py-1.5 text-slate-400">{a.target || '—'}</td>
                    <td className="py-1.5">{a.result === 'SUCCESS' ? <span className="text-emerald-400">ok</span> : <span className="text-red-400">{a.result}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}

function Row({ k, v, mono, good }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-slate-400 capitalize">{k}</span>
      <span className={`${mono ? 'font-mono text-xs' : ''} ${good !== undefined ? (good ? 'text-emerald-400' : 'text-red-400') : 'text-slate-200'}`}>{v}</span>
    </div>
  );
}
