import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import Layout from './Layout';
import { globalSearch } from '../api';
import { Empty, Loading, SeverityBadge, StatusBadge, fmtTime } from './ui';

const LABELS = {
  events: 'Events', alerts: 'Alerts', incidents: 'Incidents',
  hosts: 'Hosts', iocs: 'IOCs', users: 'Users',
};

export default function SearchPage() {
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get('q') || '');
  const [input, setInput] = useState(params.get('q') || '');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async (query) => {
    setQ(query);
    setLoading(true);
    try {
      setResult(await globalSearch(query, 8));
    } catch (e) {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const initial = params.get('q') || '';
    setQ(initial); setInput(initial);
    if (initial) run(initial);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!loading && result && q.length >= 2 && input !== q) setInput(q);
  }, [q, loading, result, input]);

  const renderRow = (group, item) => {
    switch (group) {
      case 'events':
        return (
          <div key={item.event_id} className="rounded-lg border border-slate-800 p-2 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-accent">{item.event_type}</span>
              <span className="text-[10px] text-slate-500">{fmtTime(item.ts)}</span>
            </div>
            <p className="mt-1 font-mono">{item.event_id}</p>
            <p className="mt-1 text-slate-400">{item.host || ''} · {item.source_ip || ''} · {item.username || ''}</p>
          </div>
        );
      case 'alerts':
        return (
          <div key={item.alert_id} className="rounded-lg border border-slate-800 p-2 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium">{item.title}</span>
              <div className="flex gap-2"><SeverityBadge severity={item.severity} /></div>
            </div>
            <p className="mt-1 font-mono">{item.alert_id} · {fmtTime(item.created_at)}</p>
          </div>
        );
      case 'incidents':
        return (
          <div key={item.incident_id} className="rounded-lg border border-slate-800 p-2 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium">{item.title}</span>
              <div className="flex gap-2"><StatusBadge status={item.status} /></div>
            </div>
            <p className="mt-1 font-mono">{item.incident_id} · {item.affected_host || ''}</p>
          </div>
        );
      case 'hosts':
        return (
          <div key={item.hostname} className="rounded-lg border border-slate-800 p-2 text-xs">
            <span className="font-mono">{item.hostname}</span>
            <span className="ml-2 text-slate-400">{item.ip}</span>
            {item.role ? <span className="ml-2 capitalize">{item.role}</span> : null}
          </div>
        );
      case 'iocs':
        return (
          <div key={item.ioc_id} className="rounded-lg border border-slate-800 p-2 text-xs">
            <span className="font-mono text-accent">{item.ioc_value}</span>
            <span className="ml-2 rounded-full border border-slate-700 px-1.5 py-0.5 text-[10px] uppercase">{item.ioc_type}</span>
            <span className="ml-2 text-[10px] uppercase text-slate-500">{item.verdict}</span>
            {item.threat_actor ? <span className="ml-2 text-slate-400">{item.threat_actor}</span> : null}
          </div>
        );
      case 'users':
        return (
          <div key={item.user_id} className="rounded-lg border border-slate-800 p-2 text-xs">
            <span className="font-semibold">{item.full_name || item.username}</span>
            <span className="ml-2 font-mono">{item.username}</span>
            <span className="ml-2 rounded-full border border-slate-700 px-1.5 py-0.5 text-[10px]">{item.role}</span>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <Layout title="Global Search">
      <form className="mb-4 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (input.trim().length >= 2) run(input.trim()); }}>
        <input className="input flex-1" placeholder="Search events, alerts, incidents, hosts, IOCs, users…"
          value={input} onChange={(e) => setInput(e.target.value)} />
        <button className="btn" type="submit">Search</button>
      </form>

      {loading ? <Loading label="Searching…" /> : null}

      {!loading && result && result.status === 'NO_QUERY' ? (
        <Empty message="Query must be at least 2 characters." />
      ) : null}

      {!loading && result && result.status === 'OK' ? (
        <div className="space-y-6">
          <p className="text-xs text-slate-400">{result.total} match(es) for “{result.query}” · up to {result.limit_per_group} per group</p>
          {Object.keys(LABELS).map((group) => {
            const items = result.groups?.[group] || [];
            if (items.length === 0) return null;
            return (
              <div key={group}>
                <h3 className="title mb-2">{LABELS[group]} <span className="text-slate-500">({items.length})</span></h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {items.map((item) => renderRow(group, item))}
                </div>
              </div>
            );
          })}
          {result.total === 0 ? <Empty message="No matches found." /> : null}
        </div>
      ) : null}

      {!loading && !result ? <Empty message="Enter a query above to search the corpus." /> : null}
    </Layout>
  );
}