import { useEffect, useState } from 'react';
import { listIncidents } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, StatusBadge, fmtTime } from './ui';

export default function IncidentsPage() {
  const [items, setItems] = useState([]);
  const [filters, setFilters] = useState({ status: '', severity: '' });
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await listIncidents({ ...filters, limit: 200 });
      setItems(res.items || []);
    } catch (e) {
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <Layout title="Incidents">
      <div className="mb-4 flex gap-2">
        <select className="input !w-40" value={filters.status} onChange={(e) => { setFilters({ ...filters, status: e.target.value }); load(); }}>
          <option value="">all statuses</option>
          {['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input !w-36" value={filters.severity} onChange={(e) => { setFilters({ ...filters, severity: e.target.value }); load(); }}>
          <option value="">all severities</option>
          {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {loading ? <Loading /> : items.length === 0 ? <Empty message="No incidents." /> : (
        <div className="space-y-2">
          {items.map((i) => (
            <a key={i.incident_id} href={`/incidents/${i.incident_id}`}
              className="panel block hover:border-accent/40 transition-colors"
              onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', `/incidents/${i.incident_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3 min-w-0">
                  <SeverityBadge severity={i.severity} />
                  <p className="font-medium truncate">{i.title}</p>
                </div>
                <div className="flex items-center gap-3">
                  <StatusBadge status={i.status} />
                  <span className="text-xs text-slate-400">{fmtTime(i.created_at)}</span>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
                <span>category: {i.category || '—'}</span>
                <span>risk: {i.risk_score}</span>
                <span>source: {i.source_ip || '—'}</span>
                <span>host: {i.affected_host || '—'}</span>
                <span>user: {i.affected_user || '—'}</span>
                <span>events: {(i.event_ids || []).length}</span>
              </div>
            </a>
          ))}
        </div>
      )}
    </Layout>
  );
}
