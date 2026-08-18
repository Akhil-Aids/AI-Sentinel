import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getIncident, getIncidentActions, getResponsePolicies, respondToIncident, updateIncident } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, StatusBadge, fmtTime } from './ui';

const STATUSES = ['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

export default function IncidentDetailPage() {
  const { id } = useParams();
  const [inc, setInc] = useState(null);
  const [policies, setPolicies] = useState({ actions: {} });
  const [actionHistory, setActionHistory] = useState([]);
  const [notes, setNotes] = useState('');
  const [reason, setReason] = useState('');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [i, p, a] = await Promise.all([getIncident(id), getResponsePolicies(), getIncidentActions(id)]);
      setInc(i);
      setPolicies(p);
      setActionHistory(a.items || []);
      setNotes(i.analyst_notes || '');
    } catch (e) {
      setMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [id]);

  const patch = async (payload) => {
    try {
      const updated = await updateIncident(id, payload);
      setInc(updated);
      setMsg('Updated.');
    } catch (e) {
      setMsg(e.message);
    }
    setTimeout(() => setMsg(''), 2500);
  };

  const respond = async (action, destructive) => {
    if (destructive && !window.confirm(`Execute DESTRUCTIVE action "${action}" on this incident? This cannot be undone.`)) return;
    try {
      const r = await respondToIncident(id, action, reason);
      setMsg(r.dry_run ? `Dry-run: ${r.reason}` : `${action} executed (${r.reason || 'no reason'})`);
      load();
    } catch (e) {
      setMsg(e.message);
    }
    setTimeout(() => setMsg(''), 4000);
  };

  if (loading && !inc) return <Layout title="Incident"><Loading /></Layout>;
  if (!inc) return <Layout title="Incident"><Empty message="Incident not found." /></Layout>;

  const actions = Object.entries(policies.actions || {});
  const timeline = inc.timeline || [];
  const events = inc._events || [];

  return (
    <Layout title="Incident">
      <a href="/incidents" className="text-sm text-accent hover:underline">← All incidents</a>
      {msg ? <div className="mt-3 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="mt-4 panel">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold">{inc.title}</h3>
            <p className="text-xs text-slate-400 mt-1 font-mono">{inc.incident_id} · created {fmtTime(inc.created_at)}</p>
          </div>
          <div className="flex items-center gap-3">
            <SeverityBadge severity={inc.severity} />
            <StatusBadge status={inc.status} />
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <div><p className="text-slate-400 text-xs uppercase">Risk</p><p className="mt-1 font-semibold">{inc.risk_score}/100</p></div>
          <div><p className="text-slate-400 text-xs uppercase">Category</p><p className="mt-1 capitalize">{inc.category || '—'}</p></div>
          <div><p className="text-slate-400 text-xs uppercase">Source IP</p><p className="mt-1 font-mono text-xs">{inc.source_ip || '—'}</p></div>
          <div><p className="text-slate-400 text-xs uppercase">Host / User</p><p className="mt-1">{inc.affected_host || '—'} / {inc.affected_user || '—'}</p></div>
        </div>

        {inc.ai_explanation ? (
          <div className="mt-3 rounded-lg border border-sky-400/30 bg-sky-500/10 p-3 text-sm">
            <p className="text-sky-300 text-xs uppercase tracking-wide mb-1">AI / ML Analysis</p>
            {inc.ai_explanation}
          </div>
        ) : null}

        {(inc.mitre || []).length ? (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {(inc.mitre || []).map((m) => (
              <span key={m} className="rounded-full border border-slate-700 px-2 py-0.5 text-[11px] font-mono text-slate-300">{m}</span>
            ))}
          </div>
        ) : null}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mt-4">
        <div className="xl:col-span-2 space-y-4">
          <div className="panel">
            <h3 className="title mb-3">Evidence Timeline</h3>
            {timeline.length === 0 ? <Empty message="No events linked yet." /> : (
              <div className="space-y-2 max-h-96 overflow-auto">
                {timeline.map((t, i) => (
                  <div key={i} className="flex gap-3 border-l-2 border-slate-700 pl-3">
                    <div className="min-w-0">
                      <p className="text-xs text-slate-400">{fmtTime(t.time)}</p>
                      <p className="text-sm">{t.description}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{t.type} · {t.rule} · <SeverityBadge severity={t.severity} /></p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="panel">
            <h3 className="title mb-3">Raw Events ({events.length})</h3>
            {events.length === 0 ? <Empty message="No raw events." /> : (
              <div className="space-y-2 max-h-80 overflow-auto">
                {events.map((ev) => (
                  <details key={ev.event_id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-2 text-xs">
                    <summary className="cursor-pointer font-mono">{ev.event_type} · {ev.host} · {ev.source_ip}</summary>
                    <pre className="mt-2 overflow-auto">{JSON.stringify(ev.details, null, 2)}</pre>
                  </details>
                ))}
              </div>
            )}
          </div>

          <div className="panel">
            <h3 className="title mb-3">Analyst Notes</h3>
            <textarea className="input" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)}
              placeholder="Investigation notes…" />
            <button className="btn mt-2" onClick={() => patch({ analyst_notes: notes })}>Save Notes</button>
            <div className="mt-4 flex flex-wrap gap-2">
              {STATUSES.map((s) => (
                <button key={s} className={`rounded-lg border px-3 py-1.5 text-xs ${inc.status === s ? 'border-accent/50 bg-accent/15 text-accent' : 'border-slate-700 text-slate-300 hover:bg-white/5'}`}
                  onClick={() => patch({ status: s })}>
                  Set {s}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="panel">
            <h3 className="title mb-3">Response Actions</h3>
            <input className="input" placeholder="Justification (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
            <div className="mt-3 space-y-2">
              {actions.map(([key, p]) => (
                <div key={key} className="rounded-lg border border-slate-800 p-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium">{p.label}</span>
                    <span className="text-[10px] uppercase text-slate-500">{p.permitted ? 'permitted' : 'blocked'}</span>
                  </div>
                  <button className={`mt-1 w-full rounded-lg border px-2 py-1 text-xs disabled:opacity-40 ${p.destructive ? 'border-red-400/50 bg-red-500/10 text-red-300 hover:bg-red-500/20' : 'border-accent/40 bg-accent/10 text-accent hover:bg-accent/20'}`}
                    disabled={!p.permitted} onClick={() => respond(key, p.destructive)}>
                    {p.destructive ? 'Execute (destructive)' : 'Execute'}
                  </button>
                  {p.reason ? <p className="mt-1 text-[10px] text-slate-500">{p.reason}</p> : null}
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <h3 className="title mb-3">Recommended Actions</h3>
            {(inc.recommended_actions || []).length ? (
              <ul className="list-disc pl-4 space-y-1 text-sm">
                {(inc.recommended_actions || []).map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            ) : <Empty message="No recommendations." />}
          </div>

          <div className="panel">
            <h3 className="title mb-3">Action History</h3>
            {actionHistory.length === 0 ? <Empty message="No response actions executed yet." /> : (
              <div className="space-y-2 max-h-64 overflow-auto">
                {actionHistory.map((a) => (
                  <div key={a.action_id} className="rounded-lg border border-slate-800 p-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-accent">{a.action}</span>
                      <span className="text-[10px] uppercase text-slate-500">{a.dry_run ? 'dry-run' : 'executed'}</span>
                    </div>
                    <p className="mt-1 text-slate-400">{a.reason || '—'}</p>
                    <p className="mt-1 text-[10px] text-slate-500">
                      by {a.requested_by || '—'}{a.approved_by ? ` · approved ${a.approved_by}` : ''} · {fmtTime(a.executed_at || a.created_at)}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
