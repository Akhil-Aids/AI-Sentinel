import { useEffect, useMemo, useState } from 'react';
import { getOverview, getTraffic, listAlerts, listIncidents } from '../api';
import { useLiveSocket } from '../useLiveSocket';
import Layout from './Layout';
import { Empty, Kpi, Loading, Panel, SeverityBadge, fmtTime } from './ui';

const STATUS_STYLES = {
  NO_DATA: 'bg-red-500/15 text-red-300 border-red-400/40',
  NO_EVENTS_TODAY: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  OK: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
};

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [traffic, setTraffic] = useState({ series: [], unit: 'Mbps', hosts: [] });
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [error, setError] = useState('');
  const [feed, setFeed] = useState([]);

  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const [o, t, a, i] = await Promise.all([getOverview(), getTraffic(), listAlerts(), listIncidents()]);
        if (disposed) return;
        setData(o);
        setTraffic(t);
        setAlerts(a.items || []);
        setIncidents(i.items || []);
        setError('');
      } catch (e) {
        if (!disposed) setError(e.message);
      }
    };
    load();
    const id = setInterval(load, 8000);
    return () => { disposed = true; clearInterval(id); };
  }, []);

  const { status: wsStatus } = useLiveSocket({
    onMessage: (msg) => {
      if (msg.type !== 'detection') return;
      setFeed((prev) => [{ id: msg.payload.incident_id || `${msg.sent_at}-${Math.random()}`, ...msg.payload, sent_at: msg.sent_at }, ...prev].slice(0, 12));
    },
  });

  const maxPoint = useMemo(() => Math.max(1, ...(traffic.series || [])), [traffic]);
  const trend = useMemo(() => (data?.risk_trend || []), [data]);
  const trendMax = useMemo(() => Math.max(1, ...trend.map((p) => p.max_risk)), [trend]);
  const top = data?.top_entities || { hosts: [], users: [] };

  if (!data && !error) return <Layout title="Overview"><Loading /></Layout>;

  const riskLevel = data?.risk?.level || 'low';
  const secLevel = data?.security_score?.level || 'good';
  const categories = Object.entries(data?.attack_categories || {});
  const ml = data?.ml || {};
  const dataStatus = data?.data_status || 'OK';
  const statusText = dataStatus === 'NO_DATA'
    ? 'NO DATA — no telemetry has ever been received. Sensors may be down; do not read this as "safe".'
    : dataStatus === 'NO_EVENTS_TODAY'
      ? 'NO EVENTS TODAY — telemetry received previously, but nothing in the last 24h. Check sensors.'
      : 'Telemetry flowing — no elevated risk detected.';

  return (
    <Layout title="Security Overview">
      {error ? <div className="mb-4 rounded-lg border border-red-400/40 bg-red-500/10 p-3 text-sm text-red-300">{error}</div> : null}

      <div className={`mb-4 rounded-lg border px-4 py-3 text-sm ${STATUS_STYLES[dataStatus] || STATUS_STYLES.OK}`}>
        <span className="font-semibold uppercase tracking-wide">{dataStatus}</span>
        <span className="ml-2 text-xs opacity-90">{statusText}</span>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
        <Kpi label="Environment Risk" value={data?.risk?.score ?? 0} sub={riskLevel.toUpperCase()} tone={riskLevel === 'low' ? 'emerald' : 'danger'} />
        <Kpi label="Security Score" value={data?.security_score?.score ?? 100} sub={secLevel.toUpperCase()} tone="sky" />
        <Kpi label="Open Incidents" value={data?.incidents?.open ?? 0} sub={`${data?.incidents?.total ?? 0} total`} tone="warn" />
        <Kpi label="Events Today" value={data?.events?.today ?? 0} sub={`${data?.pipeline?.eps ?? 0} EPS · queue ${data?.pipeline?.queue_depth ?? 0}`} />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
        <Kpi label="Servers Online" value={`${data?.servers?.online ?? 0}/${data?.servers?.total ?? 0}`} sub={`${data?.servers?.healthy ?? 0} healthy · ${data?.servers?.critical ?? 0} critical`} tone="emerald" />
        <Kpi label="Critical Alerts" value={data?.alerts?.critical ?? 0} tone="danger" />
        <Kpi label="High Alerts" value={data?.alerts?.high ?? 0} tone="warn" />
        <Kpi label="Detections Today" value={data?.pipeline?.detections_today ?? 0} sub="alerts raised" />
        <Kpi label="ML Model" value={ml?.enabled ? 'Active' : 'Off'} sub={ml?.model_loaded ? `v${ml?.version} · ${ml?.trained_samples} samples` : 'collecting samples…'} tone={ml?.model_loaded ? 'emerald' : 'accent'} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <Panel title="Network Throughput" className="xl:col-span-2">
          {traffic.series?.length ? (
            <>
              <div className="flex items-end gap-1 h-44">
                {traffic.series.map((p, i) => (
                  <div key={i} className="flex-1 bg-accent/60 hover:bg-accent rounded-t transition-all duration-300 min-w-0"
                    style={{ height: `${Math.max(4, (p / maxPoint) * 100)}%` }} title={`${p} ${traffic.unit}`} />
                ))}
              </div>
              <p className="mt-2 text-xs text-slate-400">
                {traffic.unit} across {traffic.hosts?.join(', ') || 'n/a'} · live real telemetry (psutil)
              </p>
            </>
          ) : <Empty message="Waiting for collector telemetry…" />}
        </Panel>

        <Panel title="Live Detection Feed">
          {feed.length ? (
            <div className="space-y-2 max-h-72 overflow-auto">
              {feed.map((d) => (
                <a key={d.id} href={`/incidents/${d.incident_id}`}
                  className="block rounded-lg border border-slate-700 hover:border-accent/40 p-2.5 transition-colors"
                  onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', `/incidents/${d.incident_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }}>
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge severity={d.severity} />
                    <span className="text-[11px] text-slate-400">{fmtTime(d.event?.time)}</span>
                  </div>
                  <p className="mt-1.5 text-sm font-semibold">{d.title}</p>
                  <p className="text-[11px] text-slate-400 mt-0.5">{d.rule} · risk {d.risk_score} · {d.category}</p>
                </a>
              ))}
            </div>
          ) : <Empty message={wsStatus === 'connected' ? 'No detections yet — watching live.' : `WebSocket ${wsStatus}…`} />}
          <p className="mt-3 text-xs text-slate-500">Real-time detections stream over WebSocket. Open an incident for full evidence.</p>
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <Panel title="7-Day Risk Trend">
          {trend.length ? (
            <>
              <div className="flex items-end gap-1 h-28">
                {trend.map((p) => (
                  <div key={p.date} className="flex-1 flex flex-col justify-end min-w-0">
                    <div className="bg-accent/60 hover:bg-accent rounded-t transition-all"
                      style={{ height: `${Math.max(4, (p.max_risk / trendMax) * 100)}%` }} title={`${p.date}: risk ${p.max_risk}`} />
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-slate-500">Peak open-incident risk per day (last 7 days). Flat line = no change.</p>
            </>
          ) : <Empty message="No incident history yet." />}
        </Panel>

        <Panel title="Top Assets by Risk">
          {top.hosts.length ? (
            <div className="space-y-1.5">
              {top.hosts.map((h) => (
                <div key={h.asset} className="flex justify-between text-sm">
                  <span className="font-mono text-xs">{h.asset}</span>
                  <span className="text-slate-400">risk {h.max_risk}</span>
                </div>
              ))}
            </div>
          ) : <Empty message="No affected hosts recorded." />}
        </Panel>

        <Panel title="Top Users by Risk">
          {top.users.length ? (
            <div className="space-y-1.5">
              {top.users.map((u) => (
                <div key={u.user} className="flex justify-between text-sm">
                  <span className="font-mono text-xs">{u.user}</span>
                  <span className="text-slate-400">risk {u.max_risk}</span>
                </div>
              ))}
            </div>
          ) : <Empty message="No affected users recorded." />}
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Panel title="Attack Categories">
          {categories.length ? (
            <div className="space-y-3">
              {categories.map(([k, v]) => {
                const max = Math.max(1, ...categories.map(([, x]) => x));
                return (
                  <div key={k}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="capitalize">{k.replace(/[_-]/g, ' ')}</span>
                      <span className="text-slate-400">{v}</span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-800">
                      <div className="h-2 rounded-full bg-accent" style={{ width: `${(v / max) * 100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : <Empty message="No categorized detections yet." />}
        </Panel>

        <Panel title="Recent Incidents">
          {incidents.length ? (
            <div className="space-y-2">
              {incidents.slice(0, 6).map((i) => (
                <a key={i.incident_id} href={`/incidents/${i.incident_id}`}
                  className="block rounded-lg border border-slate-700 hover:border-accent/40 p-3 transition-colors"
                  onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', `/incidents/${i.incident_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }}>
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium truncate">{i.title}</p>
                    <SeverityBadge severity={i.severity} />
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{i.category} · risk {i.risk_score} · {i.status}</p>
                </a>
              ))}
            </div>
          ) : <Empty message={dataStatus === 'NO_DATA' ? 'No telemetry received — incidents cannot be assessed yet.' : 'No incidents. Detection engines are monitoring live telemetry.'} />}
        </Panel>
      </div>
    </Layout>
  );
}
