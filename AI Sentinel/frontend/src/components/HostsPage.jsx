import { useEffect, useState } from 'react';
import { listHosts } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

function StatusDot({ status }) {
  const color = status === 'HEALTHY' ? 'bg-emerald-400' : status === 'DEGRADED' ? 'bg-amber-400' : 'bg-slate-500';
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />;
}

function Bar({ value, max = 100, color = 'bg-accent' }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div className="h-1.5 w-full rounded-full bg-slate-800">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export default function HostsPage() {
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const data = await listHosts();
      setHosts(data.items || []);
    } catch (e) { /* ignore */ } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); const id = setInterval(load, 10000); return () => clearInterval(id); }, []);

  return (
    <Layout title="Hosts">
      {loading && hosts.length === 0 ? <Loading /> : null}
      {!loading && hosts.length === 0 ? <Empty message="No hosts connected yet. Start an agent or collector to begin telemetry." /> : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
        {hosts.map((h) => (
          <div key={h.hostname || h.agent_id} className="panel">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">{h.hostname || h.agent_id}</h3>
                <p className="text-xs text-slate-500">{h.os || 'Unknown OS'}</p>
              </div>
              <div className="flex items-center gap-1.5">
                <StatusDot status={h.status} />
                <span className="text-xs text-slate-400">{h.status || 'UNKNOWN'}</span>
              </div>
            </div>

            <div className="space-y-2.5 text-xs">
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-slate-400">CPU</span>
                  <span className="text-slate-300">{h.cpu != null ? `${h.cpu}%` : '—'}</span>
                </div>
                <Bar value={h.cpu || 0} color={h.cpu > 80 ? 'bg-red-400' : h.cpu > 60 ? 'bg-amber-400' : 'bg-emerald-400'} />
              </div>
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-slate-400">Memory</span>
                  <span className="text-slate-300">{h.memory != null ? `${h.memory}%` : '—'}</span>
                </div>
                <Bar value={h.memory || 0} color={h.memory > 80 ? 'bg-red-400' : h.memory > 60 ? 'bg-amber-400' : 'bg-emerald-400'} />
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div className="rounded-lg bg-slate-800/50 px-2.5 py-1.5">
                  <span className="text-slate-500">Processes</span>
                  <p className="text-slate-200 font-medium">{h.processes ?? '—'}</p>
                </div>
                <div className="rounded-lg bg-slate-800/50 px-2.5 py-1.5">
                  <span className="text-slate-500">Connections</span>
                  <p className="text-slate-200 font-medium">{h.connections ?? '—'}</p>
                </div>
              </div>

              <div className="pt-1 text-slate-500">
                <span>Last heartbeat: </span>
                <span className="text-slate-400">{h.last_heartbeat_at ? fmtTime(h.last_heartbeat_at) : 'Never'}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Layout>
  );
}
