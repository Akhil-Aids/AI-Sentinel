import { useEffect, useRef, useState } from 'react';
import { listEvents, getEvent } from '../api';
import { useLiveSocket } from '../useLiveSocket';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, fmtTime } from './ui';

export default function EventsPage() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ event_type: '', host: '', severity: '', source_ip: '', environment: '', limit: 100 });
  const [selected, setSelected] = useState(null);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  const load = async (f) => {
    setLoading(true);
    try {
      const res = await listEvents(f);
      setItems(res.items || []);
      setTotal(res.total || 0);
    } catch (e) {
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(filters);
  }, []);

  const { status, paused, togglePause } = useLiveSocket({
    onMessage: (msg) => {
      if (msg.type !== 'detection') return;
      setItems((prev) => [{
        event_id: msg.payload.event?.event_id,
        ts: msg.payload.event?.time,
        event_type: msg.payload.event?.type,
        host: msg.payload.event?.host,
        source_ip: msg.payload.event?.source_ip,
        severity: msg.payload.severity,
        risk_score: msg.payload.risk_score,
        _live: msg.payload,
      }, ...prev].slice(0, 200));
    },
  });

  const open = async (id) => {
    try {
      setSelected(await getEvent(id));
    } catch (e) {
      setSelected({ event_id: id, _error: e.message });
    }
  };

  const setFilter = (k, v) => {
    const next = { ...filters, [k]: v };
    setFilters(next);
    load(next);
  };

  const wsDot = status === 'connected' ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse';

  return (
    <Layout title="Live Events">
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-3 py-1">
          <span className={`h-2 w-2 rounded-full ${wsDot}`} /> WebSocket {status}
        </span>
        <button className={`rounded-full border px-3 py-1 ${paused ? 'border-amber-400/50 text-amber-300' : 'border-slate-700 text-slate-300 hover:bg-white/5'}`}
          onClick={togglePause}>
          {paused ? 'Resume live' : 'Pause live'}
        </button>
        <input className="input !w-44" placeholder="event_type" value={filters.event_type}
          onChange={(e) => setFilter('event_type', e.target.value)} />
        <input className="input !w-36" placeholder="host" value={filters.host}
          onChange={(e) => setFilter('host', e.target.value)} />
        <select className="input !w-32" value={filters.severity} onChange={(e) => setFilter('severity', e.target.value)}>
          <option value="">all severities</option>
          {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input !w-36" value={filters.environment} onChange={(e) => setFilter('environment', e.target.value)}>
          <option value="">all environments</option>
          {['production', 'staging', 'development'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input className="input !w-40" placeholder="source IP" value={filters.source_ip}
          onChange={(e) => setFilter('source_ip', e.target.value)} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 panel">
          {loading ? <Loading /> : items.length === 0 ? <Empty message="No events match the filters." /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400 text-xs uppercase tracking-wide">
                    <th className="pb-2">Time</th>
                    <th className="pb-2">Type</th>
                    <th className="pb-2">Severity</th>
                    <th className="pb-2">Host</th>
                    <th className="pb-2">Source IP</th>
                    <th className="pb-2">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((e) => (
                    <tr key={e.event_id || `${e.ts}-${e.event_type}-${e.source_ip}`} className="border-t border-slate-800 cursor-pointer hover:bg-white/5"
                      onClick={() => open(e.event_id)}>
                      <td className="py-2 whitespace-nowrap text-slate-400">{fmtTime(e.ts)}</td>
                      <td className="py-2 font-mono text-xs">{e.event_type}</td>
                      <td className="py-2"><SeverityBadge severity={e.severity} /></td>
                      <td className="py-2">{e.host || '—'}</td>
                      <td className="py-2 font-mono text-xs">{e.source_ip || '—'}</td>
                      <td className="py-2">{e.risk_score ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-2 text-xs text-slate-500">{total} events match · showing {items.length}</p>
            </div>
          )}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Event Detail</h3>
          {!selected ? <Empty message="Click an event to inspect it." /> : selected._error ? (
            <p className="text-sm text-red-300">{selected._error}</p>
          ) : (
            <div className="space-y-2 text-sm">
              <Row k="event_id" v={selected.event_id} mono />
              <Row k="type" v={selected.event_type} />
              <Row k="time" v={fmtTime(selected.ts)} />
              <Row k="host" v={selected.host} />
              <Row k="source_ip" v={selected.source_ip} />
              <Row k="dest_ip" v={selected.dest_ip} />
              <Row k="username" v={selected.username} />
              <Row k="category" v={selected.category} />
              <Row k="environment" v={selected.environment} />
              <Row k="source type" v={selected.source_type} />
              <Row k="simulated" v={selected.is_simulated ? 'yes' : 'no'} />
              <Row k="pipeline" v={`normalized ${fmtTime(selected.normalized_at)} · processed ${fmtTime(selected.processed_at)}`} />
              {selected.detected_at ? <Row k="detected at" v={fmtTime(selected.detected_at)} /> : null}
              {selected.incident_created_at ? <Row k="incident at" v={fmtTime(selected.incident_created_at)} /> : null}
              <div>
                <p className="text-slate-400 text-xs uppercase tracking-wide mb-1">Details</p>
                <pre className="rounded-lg bg-slate-900 border border-slate-800 p-2 text-xs overflow-auto max-h-64">{JSON.stringify(selected.details, null, 2)}</pre>
              </div>
              {selected.raw && Object.keys(selected.raw).length ? (
                <div>
                  <p className="text-slate-400 text-xs uppercase tracking-wide mb-1">Raw</p>
                  <pre className="rounded-lg bg-slate-900 border border-slate-800 p-2 text-xs overflow-auto max-h-40">{JSON.stringify(selected.raw, null, 2)}</pre>
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}

function Row({ k, v, mono }) {
  if (!v && v !== 0) return null;
  return (
    <div className="flex justify-between gap-2">
      <span className="text-slate-400">{k}</span>
      <span className={mono ? 'font-mono text-xs text-right' : 'text-right'}>{v}</span>
    </div>
  );
}
