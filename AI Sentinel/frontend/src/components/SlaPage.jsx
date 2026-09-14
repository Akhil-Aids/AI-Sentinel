import { useEffect, useState } from 'react';
import { getRole, getSlaPolicies, slaIncidents, updateSlaPolicy } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, fmtTime } from './ui';

const SLA_STYLES = {
  MET: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  WITHIN_SLA: 'bg-sky-500/15 text-sky-300 border-sky-400/40',
  APPROACHING: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  BREACHED: 'bg-red-500/15 text-red-300 border-red-400/40',
  SLA_PAUSED: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
  NO_TARGET: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
};

export default function SlaPage() {
  const [policies, setPolicies] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [summary, setSummary] = useState(null);
  const [msg, setMsg] = useState('');
  const [editing, setEditing] = useState(null);
  const [minutes, setMinutes] = useState(30);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [p, i] = await Promise.all([getSlaPolicies(), slaIncidents(200)]);
      setPolicies(p.items || []);
      setIncidents(i.items || []);
      setSummary(i.summary || null);
    } catch (e) { /* ignore */ } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const save = async (sev) => {
    try {
      await updateSlaPolicy(sev, { target_minutes: minutes, enabled: true });
      flash(`SLA for ${sev} updated to ${minutes} min.`);
      setEditing(null);
      load();
    } catch (e) { flash(e.message); }
  };

  if (loading) return <Layout title="SLA Management"><Loading /></Layout>;

  return (
    <Layout title="Incident SLA">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <Stat label="Under SLA" value={summary?.sla_ok ?? 0} tone="text-emerald-300" />
        <Stat label="Approaching" value={summary?.approaching ?? 0} tone="text-amber-300" />
        <Stat label="Breached" value={summary?.breached ?? 0} tone="text-red-400" />
        <Stat label="No target" value={summary?.no_target ?? 0} tone="text-slate-400" />
      </div>

      <div className="panel mb-4">
        <h3 className="title mb-3">SLA Policies</h3>
        {policies.length === 0 ? <Empty message="No SLA policies configured." /> : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500 uppercase tracking-wide">
                <th className="pb-2">Severity</th>
                <th className="pb-2">Target</th>
                <th className="pb-2">Status</th>
                {getRole() === 'ADMIN' ? <th className="pb-2 text-right">Configure</th> : null}
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.severity} className="border-t border-slate-800">
                  <td className="py-2"><SeverityBadge severity={p.severity} /></td>
                  <td className="py-2 font-mono">
                    {editing === p.severity ? (
                      <input className="input w-24" type="number" min="1" value={minutes}
                        onChange={(e) => setMinutes(Number(e.target.value))} />
                    ) : (<>{(p.target_minutes / 60) >= 1 ? `${p.target_minutes / 60}h` : `${p.target_minutes}m`}</>)}
                  </td>
                  <td className="py-2">{p.enabled ? <span className="text-emerald-400">enabled</span> : <span className="text-slate-500">disabled</span>}</td>
                  {getRole() === 'ADMIN' ? (
                    <td className="py-2 text-right">
                      {editing === p.severity ? (
                        <span className="flex justify-end gap-2">
                          <button className="rounded border border-emerald-400/40 px-2 py-1 text-emerald-300" onClick={() => save(p.severity)}>Save</button>
                          <button className="rounded border border-slate-700 px-2 py-1" onClick={() => setEditing(null)}>Cancel</button>
                        </span>
                      ) : (
                        <button className="rounded border border-slate-700 px-2 py-1 text-slate-300"
                          onClick={() => { setEditing(p.severity); setMinutes(p.target_minutes); }}>Edit</button>
                      )}
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h3 className="title mb-3">Incidents by SLA state</h3>
        {incidents.length === 0 ? <Empty message="No incidents to evaluate." /> : (
          <div className="max-h-[28rem] overflow-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Incident</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Created</th>
                  <th className="pb-2">Elapsed</th>
                  <th className="pb-2">State</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((i) => {
                  const s = i.sla || {};
                  return (
                    <tr key={i.incident_id} className="border-t border-slate-800">
                      <td className="py-1.5"><a href={`/incidents/${i.incident_id}`} onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', `/incidents/${i.incident_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }} className="text-accent hover:underline">{i.title}</a></td>
                      <td className="py-1.5"><SeverityBadge severity={i.severity} /></td>
                      <td className="py-1.5 text-slate-500">{fmtTime(i.created_at)}</td>
                      <td className="py-1.5 font-mono">{s.elapsed_minutes != null ? `${s.elapsed_minutes}m` : '—'}</td>
                      <td className="py-1.5">
                        <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] uppercase ${SLA_STYLES[s.state] || SLA_STYLES.NO_TARGET}`}>
                          {s.state || 'NO_TARGET'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className="panel">
      <p className="label">{label}</p>
      <p className={`value ${tone}`}>{value}</p>
    </div>
  );
}