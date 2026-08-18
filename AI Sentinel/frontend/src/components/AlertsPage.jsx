import { useEffect, useState } from 'react';
import { listAlerts, updateAlert } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, fmtTime } from './ui';

const FEEDBACK = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', 'NEEDS_INVESTIGATION'];

export default function AlertsPage() {
  const [items, setItems] = useState([]);
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const res = await listAlerts({ ...filters, limit: 200 });
      setItems(res.items || []);
    } catch (e) {
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const act = async (id, payload) => {
    try {
      await updateAlert(id, payload);
      setMsg('Alert updated.');
      load();
    } catch (e) {
      setMsg(e.message);
    }
    setTimeout(() => setMsg(''), 3000);
  };

  return (
    <Layout title="Security Alerts">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}
      <div className="mb-4 flex gap-2">
        <select className="input !w-36" value={filters.severity} onChange={(e) => { setFilters({ ...filters, severity: e.target.value }); load(); }}>
          <option value="">all severities</option>
          {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input !w-36" value={filters.status} onChange={(e) => { setFilters({ ...filters, status: e.target.value }); load(); }}>
          <option value="">all statuses</option>
          {['NEW', 'ACKNOWLEDGED', 'RESOLVED'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {loading ? <Loading /> : items.length === 0 ? <Empty message="No alerts." /> : (
        <div className="space-y-2">
          {items.map((a) => (
            <div key={a.alert_id} className="panel">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3 min-w-0">
                  <SeverityBadge severity={a.severity} />
                  <p className="font-medium truncate">{a.title}</p>
                </div>
                <span className="text-xs text-slate-400">{fmtTime(a.created_at)}</span>
              </div>
              <p className="mt-1 text-xs text-slate-400">{a.description || '—'}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                <span className="text-slate-500">risk {a.risk_score} · source {a.source} · status {a.status || 'NEW'}</span>
                {a.feedback ? <span className="text-slate-400">feedback: {a.feedback}</span> : null}
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {FEEDBACK.map((f) => (
                  <button key={f} className={`rounded-lg border px-2 py-1 text-[11px] ${a.feedback === f ? 'border-accent/50 bg-accent/15 text-accent' : 'border-slate-700 text-slate-300 hover:bg-white/5'}`}
                    onClick={() => act(a.alert_id, { feedback: f })}>
                    {f.replace(/_/g, ' ').toLowerCase()}
                  </button>
                ))}
                <span className="flex-1" />
                {a.status === 'NEW'
                  ? <button className="rounded-lg border border-emerald-400/40 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/10" onClick={() => act(a.alert_id, { status: 'RESOLVED' })}>Resolve</button>
                  : <button className="rounded-lg border border-slate-600 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/5" onClick={() => act(a.alert_id, { status: 'NEW' })}>Reopen</button>}
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
