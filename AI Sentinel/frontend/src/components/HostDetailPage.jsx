import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getHost } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, StatusBadge, fmtTime, riskStyles } from './ui';

function Spark({ data, color = 'bg-accent' }) {
  return (
    <div className="flex h-16 items-end gap-0.5">
      {data.map((v, i) => (
        <div key={i} className={`flex-1 ${color} ${v === 0 ? 'opacity-20' : ''}`}
          style={{ height: `${Math.min(100, Math.max(3, v || 1))}%`, opacity: v === 0 ? 0.15 : 0.45 + (v / 100) * 0.55 }} />
      ))}
    </div>
  );
}

export default function HostDetailPage() {
  const { hostname } = useParams();
  const [host, setHost] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      setHost(await getHost(hostname));
      setErr('');
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [hostname]);

  if (loading && !host) return <Layout title="Host"><Loading /></Layout>;
  if (!host) return <Layout title="Host"><Empty message={err || 'Host not found.'} /></Layout>;

  const stats = host.stats || [];
  const events = host.events || [];
  const alerts = host.alerts || [];
  const incidents = host.incidents || [];
  const network = host.network || [];

  return (
    <Layout title="Host Investigation">
      <a href="/hosts" className="text-sm text-accent hover:underline">← All hosts</a>

      <div className="mt-4 panel">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold font-mono">{host.hostname}</h3>
            <p className="text-xs text-slate-400 mt-1">{host.os || 'Unknown OS'} · {host.platform || '—'}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-sm font-semibold ${riskStyles(host.risk_band)}`}>Risk {host.risk_score}/100</span>
            <span className="rounded-full border border-slate-700 px-2 py-0.5 text-[11px] uppercase text-slate-300">{host.status || 'UNKNOWN'}</span>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <div><p className="text-slate-400 uppercase">CPU</p><p className="mt-1 text-sm font-semibold">{host.cpu != null ? `${host.cpu}%` : '—'}</p></div>
          <div><p className="text-slate-400 uppercase">Memory</p><p className="mt-1 text-sm font-semibold">{host.memory != null ? `${host.memory}%` : '—'}</p></div>
          <div><p className="text-slate-400 uppercase">Processes</p><p className="mt-1 text-sm font-semibold">{host.processes ?? '—'}</p></div>
          <div><p className="text-slate-400 uppercase">Open Alerts</p><p className="mt-1 text-sm font-semibold">{alerts.filter((a) => a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE').length}</p></div>
          <div><p className="text-slate-400 uppercase">Open Incidents</p><p className="mt-1 text-sm font-semibold">{incidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE').length}</p></div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 mt-4 lg:grid-cols-2">
        <div className="panel">
          <h3 className="title mb-3">CPU history (last {stats.length} samples)</h3>
          {stats.length ? <Spark data={stats.map((s) => s.cpu || 0)} color="bg-sky-400" /> : <Empty message="No history yet." />}
          <h3 className="title mt-4 mb-3">Memory history</h3>
          {stats.length ? <Spark data={stats.map((s) => s.memory || 0)} color="bg-accent" /> : <Empty />}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Alerts on this host ({alerts.length})</h3>
          {alerts.length === 0 ? <Empty message="No alerts reference this host." /> : (
            <div className="space-y-2 max-h-72 overflow-auto">
              {alerts.map((a) => (
                <a key={a.alert_id} href={`/alerts`} onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', '/alerts'); window.dispatchEvent(new PopStateEvent('popstate')); }}
                  className="block rounded-lg border border-slate-800 p-2 hover:border-slate-600">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium truncate">{a.title}</span>
                    <SeverityBadge severity={a.severity} />
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">{a.rule_name || a.rule_id} · {fmtTime(a.created_at)}</p>
                </a>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 panel">
        <h3 className="title mb-3">Incidents affecting this host ({incidents.length})</h3>
        {incidents.length === 0 ? <Empty message="No incidents linked to this host." /> : (
          <div className="space-y-2">
            {incidents.map((inc) => (
              <a key={inc.incident_id} href={`/incidents/${inc.incident_id}`} className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 p-2 hover:border-slate-600">
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">{inc.title}</p>
                  <p className="text-[11px] text-slate-500">{inc.category} · {fmtTime(inc.created_at)}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <StatusBadge status={inc.status} />
                  <SeverityBadge severity={inc.severity} />
                </div>
              </a>
            ))}
          </div>
        )}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="panel">
          <h3 className="title mb-3">Recent events on this host ({events.length})</h3>
          {events.length === 0 ? <Empty message="No events yet." /> : (
            <div className="space-y-1.5 max-h-96 overflow-auto">
              {events.map((ev) => (
                <details key={ev.event_id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-2 text-xs">
                  <summary className="cursor-pointer font-mono flex flex-wrap gap-2">
                    <span className="text-accent">{ev.event_type}</span>
                    <span className="text-slate-500">{fmtTime(ev.ts)}</span>
                    <span className="text-slate-400">{ev.source_ip}{ev.dest_ip ? ` → ${ev.dest_ip}` : ''}</span>
                  </summary>
                  <pre className="mt-2 overflow-auto text-slate-400">{JSON.stringify(ev.details, null, 2)}</pre>
                </details>
              ))}
            </div>
          )}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Network activity ({network.length})</h3>
          {network.length === 0 ? <Empty message="No network connections captured." /> : (
            <div className="space-y-1.5 max-h-96 overflow-auto">
              {network.map((n) => (
                <div key={n.id} className="rounded-lg border border-slate-800 px-2 py-1.5 text-xs font-mono flex flex-wrap gap-2 justify-between">
                  <span className="text-slate-400">{fmtTime(n.ts)}</span>
                  <span className="text-accent">{n.event_type}</span>
                  <span className="text-slate-300">{n.source_ip} → {n.dest_ip}:{n.port}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}