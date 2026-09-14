import { useEffect, useState } from 'react';
import { deleteHunt, huntHistory, listHuntPatterns, listHunts, runHunt, runSavedHunt, saveHunt } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

const STATUS_TONE = {
  NO_DATA: 'text-slate-400',
  NO_MATCHES: 'text-sky-300',
  OK: 'text-emerald-300',
  ERROR: 'text-red-300',
};

export default function ThreatHuntingPage() {
  const [patterns, setPatterns] = useState([]);
  const [saved, setSaved] = useState([]);
  const [filters, setFilters] = useState({});
  const [groupBy, setGroupBy] = useState('');
  const [minGroup, setMinGroup] = useState(1);
  const [limit, setLimit] = useState(500);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [viewing, setViewing] = useState(null);
  const [msg, setMsg] = useState('');

  const load = async () => {
    try {
      const [p, h] = await Promise.all([listHuntPatterns(), listHunts()]);
      setPatterns(p.items || []);
      setSaved(h.items || []);
    } catch (e) { /* ignore */ }
  };

  useEffect(() => { load(); }, []);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3500); };

  const run = async (f, lim = null) => {
    setLoading(true);
    setResult(null);
    try {
      const payload = { ...f };
      if (groupBy) payload.group_by = groupBy;
      if (lim === null && minGroup > 1) payload.min_group_count = minGroup;
      const res = await runHunt(payload, lim ?? limit);
      setResult(res);
    } catch (e) {
      flash(e.message);
    } finally {
      setLoading(false);
    }
  };

  const runPattern = async (pattern, filtersOverride = {}) => {
    const f = { ...(filtersOverride || {}), pattern };
    setResult(null);
    setLoading(true);
    try {
      setResult(await runHunt(f, limit));
    } catch (e) {
      flash(e.message);
    } finally {
      setLoading(false);
    }
  };

  const saveCurrent = async () => {
    if (!saveName.trim()) return;
    try {
      const payload = { name: saveName, description: '', query_text: '', filters: { pattern: filters.pattern } };
      if (groupBy) payload.filters.group_by = groupBy;
      await saveHunt(payload);
      setSaveName('');
      flash('Hunt saved.');
      load();
    } catch (e) { flash(e.message); }
  };

  const renderRows = () => {
    if (!result) return null;
    const msgText = ((result.message) || '').replace(/[•\n]/g, ' ');
    const aggregate = result.aggregate !== undefined;
    const rows = result.rows || result.matches || [];
    return (
      <div className="panel mt-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="title">Run Result</h3>
            <p className={`text-xs mt-0.5 ${STATUS_TONE[result.status] || 'text-slate-300'}`}>
              {result.status}{result.duration_ms != null ? ` · ${result.duration_ms} ms` : ''} · {result.count} row(s)
              {msgText && result.status === 'OK' ? ` · ${msgText}` : ''}
            </p>
          </div>
          {aggregate ? <span className="text-xs text-slate-400">grouped by {result.group_by}</span> : null}
        </div>
        {rows.length === 0 ? <Empty message={result.status === 'NO_DATA' ? 'No data in the hunt window.' : 'No matches found.'} /> : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  {Array.from(new Set(rows.flatMap((r) => Object.keys(r)))).map((k) => <th key={k} className="px-2 py-1.5 font-medium">{k}</th>)}
                  {aggregate ? null : <th className="px-2 py-1.5 font-medium">Time</th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className="border-b border-slate-800/60">
                    {Array.from(new Set(rows.flatMap((x) => Object.keys(x)))).map((k) => (
                      <td key={k} className="px-2 py-1.5 font-mono text-slate-300">{r[k] ?? '—'}</td>
                    ))}
                    {aggregate ? null : <td className="px-2 py-1.5 text-slate-500">{fmtTime(r.ts)}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  return (
    <Layout title="Threat Hunting">
      {msg ? <div className="mb-3 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="space-y-4 xl:col-span-2">
          <div className="panel">
            <h3 className="title mb-3">Named Hunt Patterns</h3>
            {patterns.length === 0 ? <Empty message="No patterns available." /> : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {patterns.map((p) => (
                  <div key={p.key} className="rounded-lg border border-slate-800 p-3">
                    <p className="text-sm font-semibold">{p.label}</p>
                    <p className="mt-1 text-[11px] text-slate-400">{p.description}</p>
                    <button className="mt-2 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1 text-xs text-accent hover:bg-accent/20"
                      disabled={loading} onClick={() => runPattern(p.key, p.filters)}>
                      Run hunt
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="panel">
            <h3 className="title mb-3">Custom Hunt</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              <label className="block text-xs text-slate-400">Pattern
                <select className="input mt-1" value={filters.pattern || ''} onChange={(e) => setFilters({ ...filters, pattern: e.target.value })}>
                  <option value="">— none —</option>
                  {patterns.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Event type
                <input className="input mt-1 font-mono" value={filters.event_type || ''} onChange={(e) => setFilters({ ...filters, event_type: e.target.value })} placeholder="auth.failed_login" />
              </label>
              <label className="block text-xs text-slate-400">Source IP
                <input className="input mt-1 font-mono" value={filters.source_ip || ''} onChange={(e) => setFilters({ ...filters, source_ip: e.target.value })} />
              </label>
              <label className="block text-xs text-slate-400">Username
                <input className="input mt-1 font-mono" value={filters.username || ''} onChange={(e) => setFilters({ ...filters, username: e.target.value })} />
              </label>
              <label className="block text-xs text-slate-400">Severity min
                <select className="input mt-1" value={filters.severity_min || ''} onChange={(e) => setFilters({ ...filters, severity_min: e.target.value })}>
                  <option value="">— any —</option>
                  {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Group by
                <select className="input mt-1" value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
                  <option value="">— none —</option>
                  {['source_ip', 'dest_ip', 'username', 'host', 'event_type', 'category', 'process', 'environment'].map((g) => <option key={g} value={g}>{g}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Min group count
                <input className="input mt-1" type="number" min={1} value={minGroup} onChange={(e) => setMinGroup(Number(e.target.value) || 1)} />
              </label>
              <label className="block text-xs text-slate-400">Limit
                <input className="input mt-1" type="number" min={1} value={limit} onChange={(e) => setLimit(Number(e.target.value) || 500)} />
              </label>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button className="btn" disabled={loading} onClick={() => run(filters)}>Run Custom Hunt</button>
              <input className="input w-56" placeholder="Save hunt as…" value={saveName} onChange={(e) => setSaveName(e.target.value)} />
              <button className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-white/5" onClick={saveCurrent} disabled={!saveName.trim()}>Save Hunt</button>
            </div>
          </div>
        </div>

        <div>
          <div className="panel">
            <h3 className="title mb-3">Saved Hunts</h3>
            {saved.length === 0 ? <Empty message="No saved hunts yet." /> : (
              <div className="space-y-2">
                {saved.map((h) => (
                  <div key={h.hunt_id} className="rounded-lg border border-slate-800 p-2">
                    <p className="text-xs font-semibold">{h.name}</p>
                    <p className="mt-0.5 text-[10px] font-mono text-slate-500">{h.hunt_id}</p>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      <button className="rounded border border-accent/40 px-2 py-0.5 text-[11px] text-accent hover:bg-accent/10" disabled={loading} onClick={async () => {
                        try { setResult(await runSavedHunt(h.hunt_id)); } catch (e) { flash(e.message); }
                      }}>Run</button>
                      <button className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-white/5" onClick={async () => {
                        try { setViewing({ hunt: h, history: (await huntHistory(h.hunt_id)).items || [] }); } catch (e) { flash(e.message); }
                      }}>History</button>
                      <button className="rounded border border-red-400/40 px-2 py-0.5 text-[11px] text-red-300 hover:bg-red-500/10" onClick={async () => {
                        if (!window.confirm(`Delete hunt "${h.name}"?`)) return;
                        try { await deleteHunt(h.hunt_id); flash('Hunt deleted.'); load(); } catch (e) { flash(e.message); }
                      }}>Delete</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {loading ? <Loading label="Running hunt…" /> : renderRows()}

      {viewing ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setViewing(null)}>
          <div className="panel max-w-lg w-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="title">Run History: {viewing.hunt.name}</h3>
              <button className="text-slate-400 hover:text-white" onClick={() => setViewing(null)}>✕</button>
            </div>
            {viewing.history.length === 0 ? <Empty message="No runs yet." /> : (
              <div className="mt-3 max-h-72 overflow-auto space-y-2">
                {viewing.history.map((r) => (
                  <div key={r.run_id} className="rounded-lg border border-slate-800 p-2 text-xs">
                    <span className="text-accent">{r.result_count} matches</span>
                    <span className="ml-2 text-slate-500">{r.duration_ms} ms</span>
                    <p className="mt-1 text-[10px] text-slate-500">{fmtTime(r.ran_at)}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </Layout>
  );
}