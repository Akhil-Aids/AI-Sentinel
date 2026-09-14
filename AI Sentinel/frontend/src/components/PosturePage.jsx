import { useEffect, useState } from 'react';
import { postureHistory, postureNow, postureRecord } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

function tone(status) {
  switch (status) {
    case 'GOOD': return 'text-emerald-300';
    case 'FAIR': case 'NO_TARGET': return 'text-accent';
    case 'POOR': return 'text-amber-300';
    default: return 'text-red-400';
  }
}

export default function PosturePage() {
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [msg, setMsg] = useState('');

  const load = async () => {
    try {
      const [n, h] = await Promise.all([postureNow(), postureHistory()]);
      setData(n);
      setHistory(h.items || []);
    } catch (e) { /* ignore */ }
  };

  useEffect(() => { load(); }, []);

  const record = async () => {
    try {
      const s = await postureRecord();
      setMsg(`Snapshot recorded — score ${s.score}, ${s.status}.`);
      setTimeout(() => setMsg(''), 3000);
      load();
    } catch (e) { setMsg(e.message); setTimeout(() => setMsg(''), 3000); }
  };

  if (!data) return <Layout title="Security Posture"><Loading /></Layout>;

  const pct = Math.min(100, Math.max(0, data.score));

  return (
    <Layout title="Security Posture">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="panel flex flex-col items-center justify-center">
          <p className={`text-5xl font-bold ${tone(data.status)}`}>{Math.round(data.score)}</p>
          <p className={`mt-1 text-sm uppercase tracking-widest ${tone(data.status)}`}>{data.status}</p>
          <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div className={`h-full rounded-full ${data.status === 'GOOD' ? 'bg-emerald-400' : data.status === 'FAIR' ? 'bg-accent' : data.status === 'POOR' ? 'bg-amber-400' : 'bg-red-400'}`}
              style={{ width: `${pct}%` }} />
          </div>
          <p className="mt-1 text-[10px] text-slate-500">computed {data.computed_at ? fmtTime(data.computed_at) : '—'}</p>
          <button className="btn mt-3" onClick={record}>Record snapshot</button>
        </div>

        <div className="panel lg:col-span-2">
          <h3 className="title mb-3">Score Factors (every delta is data-derived)</h3>
          {(data.factors || []).length === 0 ? <Empty /> : (
            <div className="space-y-2">
              {data.factors.map((f) => (
                <div key={f.factor} className="flex items-center justify-between rounded-lg border border-slate-800 p-2 text-sm">
                  <div className="min-w-0">
                    <p className="font-medium capitalize">{f.factor.replace(/_/g, ' ')}</p>
                    <p className="truncate text-[11px] text-slate-500">{f.msg || f.detail}</p>
                  </div>
                  <span className={`ml-3 font-mono text-base ${(f.factor_delta || 0) < 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {f.factor_delta > 0 ? '+' : ''}{f.factor_delta}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="panel">
          <h3 className="title mb-3">Coverage snapshot</h3>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <Metric k="Techniques covered" v={data.coverage?.techniques_covered} />
            <Metric k="Verified live" v={data.coverage?.verified_live} />
            <Metric k="Observed, no rules" v={data.coverage?.observed_no_rules} />
            <Metric k="Rules disabled" v={data.coverage?.rules_disabled} />
          </div>
        </div>

        <div className="panel">
          <h3 className="title mb-3">Posture History</h3>
          {history.length === 0 ? <Empty message="No snapshots recorded yet — hit “Record snapshot”." /> : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Score</th>
                  <th className="pb-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="border-t border-slate-800">
                    <td className="py-1.5 text-slate-500">{fmtTime(h.created_at)}</td>
                    <td className="py-1.5 font-mono text-accent">{h.score}</td>
                    <td className={`py-1.5 font-mono ${tone(h.status)}`}>{h.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Layout>
  );
}

function Metric({ k, v }) {
  return (
    <div className="rounded-lg border border-slate-800 p-2">
      <p className="text-[10px] uppercase tracking-wide text-slate-500">{k}</p>
      <p className="font-mono text-lg text-accent">{v ?? '—'}</p>
    </div>
  );
}