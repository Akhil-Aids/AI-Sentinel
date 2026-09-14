import { useEffect, useState } from 'react';
import { dataQualityOverview } from '../api';
import Layout from './Layout';
import { Empty, Loading } from './ui';

const PRIORITY_STYLES = { critical: 'text-red-400', high: 'text-amber-300', medium: 'text-sky-300', low: 'text-slate-400' };
const INTEGRITY_STYLES = { VERIFIED: 'text-emerald-400', PENDING: 'text-amber-300', TAMPERED: 'text-red-400', NOT_APPLICABLE: 'text-slate-500' };

export default function DataQualityPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    dataQualityOverview().then(setData).catch(() => setData(null)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Layout title="Data Quality"><Loading /></Layout>;

  const ov = data?.overview || {};
  const sources = data?.by_source || [];
  const integrity = data?.evidence_integrity || {};
  const recs = data?.recommendations || [];

  return (
    <Layout title="Data Quality Center">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <Stat label="Ingested" value={ov.total_ingested ?? 0} tone="text-accent" />
        <Stat label="Normalised" value={ov.normalized ?? 0} sub={ov.normalisation_rate != null ? `${ov.normalisation_rate}%` : '—'} tone="text-emerald-300" />
        <Stat label="Unprocessed" value={ov.unprocessed ?? 0} tone="text-amber-300" />
        <Stat label="Errored (24h)" value={ov.errored ?? 0} tone="text-red-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="panel">
          <h3 className="title mb-3">Pipeline Health</h3>
          <div className="space-y-2 text-sm">
            <Metric k="processed" v={ov.processed} />
            <Metric k="detection matched" v={ov.detection_matched} />
            <Metric k="events / source" v="below" />
            <Metric k="avg ingest→normalise lag" v={ov.lag_seconds != null ? `${ov.lag_seconds}s` : '—'} />
          </div>
        </div>

        <div className="panel">
          <h3 className="title mb-3">By Source</h3>
          {sources.length === 0 ? <Empty message="No telemetry sources yet." /> : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Source</th>
                  <th className="pb-2">Events</th>
                  <th className="pb-2">%</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.source} className="border-t border-slate-800">
                    <td className="py-1.5 font-mono">{s.source}</td>
                    <td className="py-1.5 font-mono text-accent">{s.events}</td>
                    <td className="py-1.5 text-slate-400">{s.pct}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Evidence Integrity</h3>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <Metric k="records" v={integrity.records ?? 0} />
            <Metric k="verified" v={integrity.verified ?? 0} />
            <Metric k="pending" v={integrity.pending ?? 0} />
            <Metric k="tampered" v={integrity.tampered ?? 0} />
          </div>
          {Object.entries(integrity.by_status || {}).length > 0 ? (
            <div className="mt-3 space-y-1">
              {Object.entries(integrity.by_status).map(([k, v]) => (
                <p key={k} className="text-[11px] uppercase tracking-wide">
                  <span className={INTEGRITY_STYLES[k] || INTEGRITY_STYLES.NOT_APPLICABLE}>{k}</span>
                  <span className="ml-2 font-mono text-slate-400">{v}</span>
                </p>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      <div className="panel">
        <h3 className="title mb-3">Recommendations</h3>
        {recs.length === 0 ? <Empty message="No pipeline issues flagged from the live store." /> : (
          <div className="space-y-2">
            {recs.map((r, i) => (
              <div key={i} className="flex items-start justify-between gap-3 rounded-lg border border-slate-800 p-2.5 text-sm">
                <p className="text-slate-300">{r.recommendation}</p>
                <span className={`shrink-0 font-medium ${PRIORITY_STYLES[r.priority] || PRIORITY_STYLES.medium}`}>{r.priority.toUpperCase()}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}

function Stat({ label, value, sub, tone }) {
  return (
    <div className="panel">
      <p className="label">{label}</p>
      <p className={`value ${tone}`}>{value}</p>
      {sub ? <p className="text-xs text-slate-400 mt-1">{sub}</p> : null}
    </div>
  );
}

function Metric({ k, v }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-slate-400 capitalize">{k}</span>
      <span className="font-mono text-slate-200">{v ?? '—'}</span>
    </div>
  );
}