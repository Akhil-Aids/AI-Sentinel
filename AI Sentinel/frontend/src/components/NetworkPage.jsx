import { useEffect, useMemo, useState } from 'react';
import { getNetworkConnections, getNetworkTop, getServers, getTraffic } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

function Spark({ values }) {
  const max = Math.max(1, ...values);
  return (
    <div className="flex items-end gap-0.5 h-12">
      {values.map((v, i) => (
        <div key={i} className="flex-1 rounded-t bg-accent/60" style={{ height: `${Math.max(4, (v / max) * 100)}%` }} title={`${v}`} />
      ))}
    </div>
  );
}

export default function NetworkPage() {
  const [servers, setServers] = useState([]);
  const [traffic, setTraffic] = useState({ series: [], unit: 'Mbps', hosts: [] });
  const [top, setTop] = useState({ sources: [], destinations: [], ports: [] });
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [s, t, tp, c] = await Promise.all([getServers(), getTraffic(), getNetworkTop(), getNetworkConnections()]);
      setServers(s.items || []);
      setTraffic(t);
      setTop(tp);
      setConnections(c.items || []);
    } catch (e) { /* ignore */ } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); const id = setInterval(load, 10000); return () => clearInterval(id); }, []);

  const maxPoint = useMemo(() => Math.max(1, ...(traffic.series || [])), [traffic]);

  return (
    <Layout title="Network">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <div className="panel xl:col-span-2">
          <h3 className="title mb-3">Aggregate Throughput ({traffic.unit})</h3>
          {traffic.series?.length ? (
            <>
              <div className="flex items-end gap-1 h-48">
                {traffic.series.map((p, i) => (
                  <div key={i} className="flex-1 bg-accent/60 hover:bg-accent rounded-t transition-all" style={{ height: `${Math.max(4, (p / maxPoint) * 100)}%` }} title={`${p} ${traffic.unit}`} />
                ))}
              </div>
              <p className="mt-2 text-xs text-slate-400">current {traffic.current} {traffic.unit} · hosts: {traffic.hosts?.join(', ') || 'n/a'}</p>
            </>
          ) : <Empty message="Waiting for collector telemetry…" />}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Live Connections</h3>
          {connections.length ? (
            <div className="max-h-72 overflow-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-slate-500 uppercase tracking-wide">
                    <th className="pb-2">Src</th>
                    <th className="pb-2">Dst</th>
                    <th className="pb-2">Port</th>
                    <th className="pb-2">When</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.slice(0, 12).map((c) => (
                    <tr key={c.event_id || `${c.ts}-${c.source_ip}`} className="border-t border-slate-800">
                      <td className="py-1.5 font-mono">{c.source_ip || '—'}</td>
                      <td className="py-1.5 font-mono">{c.dest_ip || '—'}</td>
                      <td className="py-1.5">{c.dest_port ?? c.port ?? '—'}</td>
                      <td className="py-1.5 whitespace-nowrap text-slate-500">{fmtTime(c.ts)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="text-xs text-slate-400">Real connection counts tracked by the psutil-based collector (TCP/UDP).</p>}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <TopPanel title={`Top Sources (${top.window_minutes || 60}m)`} rows={(top.sources || []).map((s) => ({ key: s.ip, value: s.connections, mono: true }))} />
        <TopPanel title={`Top Destinations (${top.window_minutes || 60}m)`} rows={(top.destinations || []).map((d) => ({ key: d.ip, value: d.connections, mono: true }))} />
        <TopPanel title={`Top Ports (${top.window_minutes || 60}m)`} rows={(top.ports || []).map((p) => ({ key: String(p.port), value: p.connections }))} />
      </div>

      <h3 className="title mb-3">Servers</h3>
      {loading ? <Loading /> : servers.length === 0 ? <Empty message="No server telemetry yet." /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {servers.map((s) => {
            const history = s.history || [];
            const last = history[history.length - 1];
            const baseline = s.baseline || {};
            const devs = baseline.deviations || [];
            return (
              <div key={s.hostname} className="panel">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <p className="font-semibold">{s.hostname}</p>
                    <p className="text-xs text-slate-500 font-mono">{s.ip || s.os || '—'} · {s.os || 'unknown os'} · {s.environment || 'dev'}</p>
                  </div>
                  <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] ${s.status === 'online' ? 'border-emerald-400/40 text-emerald-300' : 'border-red-400/40 text-red-300'}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${s.status === 'online' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                    {s.status}
                  </span>
                </div>
                {last ? (
                  <div className="mt-3 grid grid-cols-4 gap-2 text-center text-xs">
                    <Metric label="CPU" value={`${last.cpu ?? 0}%`} />
                    <Metric label="Memory" value={`${last.memory ?? 0}%`} />
                    <Metric label="Disk" value={`${last.disk ?? 0}%`} />
                    <Metric label="Procs" value={last.processes ?? 0} />
                  </div>
                ) : <p className="mt-3 text-xs text-slate-500">No stats yet.</p>}
                <div className="mt-3">
                  <p className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">Network (Mbps)</p>
                  <Spark values={history.map((h) => h.network_mbps || 0)} />
                </div>
                {devs.length ? (
                  <div className="mt-3 rounded-lg border border-amber-400/30 bg-amber-500/10 p-2">
                    <p className="text-[10px] uppercase tracking-wide text-amber-300 mb-1">Baseline deviation (z ≥ 2)</p>
                    {devs.map((d) => (
                      <p key={d.metric} className="text-[11px] text-slate-300">
                        {d.metric}: current <b>{d.current}</b> vs baseline {d.baseline_mean}±{d.baseline_std} (z={d.z_score})
                      </p>
                    ))}
                  </div>
                ) : null}
                <p className="mt-2 text-[11px] text-slate-500">last seen {fmtTime(last?.collected_at)} · baseline from {baseline.samples ?? 0} samples</p>
              </div>
            );
          })}
        </div>
      )}
    </Layout>
  );
}

function TopPanel({ title, rows }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="panel">
      <h3 className="title mb-3">{title}</h3>
      {rows.length === 0 ? <Empty message="No connection events in window." /> : (
        <div className="space-y-2">
          {rows.map((r) => (
            <div key={r.key} className="flex items-center gap-2">
              <span className={`w-36 truncate text-xs ${r.mono ? 'font-mono' : ''}`}>{r.key}</span>
              <div className="flex-1 h-2 rounded-full bg-slate-800">
                <div className="h-2 rounded-full bg-accent" style={{ width: `${Math.max(4, (r.value / max) * 100)}%` }} />
              </div>
              <span className="text-xs text-slate-400 w-8 text-right">{r.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
      <p className="text-[10px] uppercase text-slate-500">{label}</p>
      <p className="font-semibold mt-0.5">{value}</p>
    </div>
  );
}
