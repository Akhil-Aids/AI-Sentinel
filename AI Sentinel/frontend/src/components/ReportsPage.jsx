import { useEffect, useState } from 'react';
import { createDailyReport, createPostureReport, deleteReport, listReports } from '../api';
import { getRole } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

function TypeBadge({ type }) {
  const map = { daily: 'text-accent border-accent/40', posture: 'text-sky-300 border-sky-400/40', incident: 'text-warn border-amber-400/40' };
  return <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide ${map[type] || 'text-slate-300 border-slate-700'}`}>{type}</span>;
}

function StateLine({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1">
      <span className="text-slate-400 text-xs shrink-0">{label}</span>
      <span className="text-sm text-right">{value}</span>
    </div>
  );
}

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');
  const [selected, setSelected] = useState(null);
  const role = getRole();
  const canEdit = role === 'SOC_ANALYST' || role === 'SECURITY_ENGINEER' || role === 'ADMIN';
  const canDelete = role === 'SECURITY_ENGINEER' || role === 'ADMIN';

  const load = async () => {
    setLoading(true);
    try {
      const data = await listReports();
      setReports(data.items || []);
    } catch (e) { show(e.message); } finally { setLoading(false); }
  };

  const show = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3500); };

  useEffect(() => { load(); }, []);

  const generate = async (kind, payload = {}) => {
    setBusy(kind);
    try {
      if (kind === 'daily') await createDailyReport(payload);
      if (kind === 'posture') await createPostureReport();
      show('Report generated and stored with audit trail.');
      await load();
    } catch (e) { show(e.message); } finally { setBusy(''); }
  };

  const remove = async (id) => {
    if (!window.confirm('Delete this report?')) return;
    try { await deleteReport(id); setSelected(null); await load(); } catch (e) { show(e.message); }
  };

  const open = async (rep) => {
    try {
      const detail = await listReports();
      const full = (detail.items || []).find((r) => r.report_id === rep.report_id) || rep;
      setSelected(full);
    } catch (e) { show(e.message); }
  };

  return (
    <Layout title="Reports">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      {canEdit ? (
        <div className="panel mb-4">
          <h3 className="title mb-3">Generate report</h3>
          <div className="flex flex-wrap gap-2">
            <button className="btn" disabled={busy === 'daily'} onClick={() => generate('daily')}>
              {busy === 'daily' ? 'Generating…' : 'Daily SOC Report'}
            </button>
            <button className="btn" disabled={busy === 'posture'} onClick={() => generate('posture')}>
              {busy === 'posture' ? 'Generating…' : 'Security Posture Report'}
            </button>
            <span className="text-xs text-slate-500 self-center ml-1">Incident reports are generated from the incident detail page.</span>
          </div>
        </div>
      ) : null}

      {loading && reports.length === 0 ? <Loading /> : null}
      {!loading && reports.length === 0 ? <Empty message="No reports generated yet." /> : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="panel">
          <h3 className="title mb-3">Stored reports ({reports.length})</h3>
          {reports.length === 0 ? <Empty message="No reports." /> : (
            <div className="space-y-2 max-h-[32rem] overflow-auto">
              {reports.map((r) => (
                <button key={r.report_id} onClick={() => open(r)}
                  className={`w-full text-left rounded-lg border p-2 hover:border-slate-600 ${selected?.report_id === r.report_id ? 'border-accent/50 bg-accent/10' : 'border-slate-800'}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium truncate">{r.title}</span>
                    <TypeBadge type={r.report_type} />
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">{fmtTime(r.created_at)} · by {r.created_by || '—'}</p>
                  <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">{r.summary || ''}</p>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Report detail</h3>
          {!selected ? <Empty message="Select a report to inspect its findings." /> : (
            <div className="max-h-[32rem] overflow-auto pr-1">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-semibold">{selected.title}</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">{selected.report_id} · {fmtTime(selected.created_at)}</p>
                </div>
                <TypeBadge type={selected.report_type} />
              </div>
              <div className="mt-3 rounded-lg border border-amber-400/30 bg-amber-500/10 p-3">
                <p className="text-[10px] uppercase tracking-wide text-amber-300 mb-1">Summary</p>
                <p className="text-sm">{selected.summary || ''}</p>
              </div>

              {selected.report_type === 'daily' && selected.content ? (
                <div className="mt-4 space-y-4 text-sm">
                  <StateLine label="Period" value={`${selected.content.period?.start ?? ''} → ${selected.content.period?.end ?? ''}`} />
                  <StateLine label="Events" value={selected.content.events?.total ?? '—'} />
                  <StateLine label="Alerts" value={selected.content.alerts?.total ?? '—'} />
                  <StateLine label="Open incidents" value={selected.content.incidents?.open ?? '—'} />
                  <StateLine label="Detections by rule" value={(selected.content.alerts?.by_severity?.critical ?? 0) + (selected.content.alerts?.by_severity?.high ?? 0)} />
                </div>
              ) : null}

              {selected.report_type === 'posture' && selected.content ? (
                <div className="mt-4 space-y-4 text-sm">
                  <StateLine label="Security score" value={`${selected.content.security_score ?? '—'}/100`} />
                  <StateLine label="Risk band" value={selected.content.risk_band ?? '—'} />
                  <StateLine label="Asset health" value={selected.content.assets ? `${selected.content.assets.online || 0}/${selected.content.assets.total || 0} online` : '—'} />
                  <StateLine label="Open incidents" value={selected.content.incidents?.open ?? '—'} />
                  <StateLine label="Top category" value={selected.content.incidents?.top_category ?? '—'} />
                </div>
              ) : null}

              {selected.report_type === 'incident' && selected.content ? (
                <div className="mt-4 space-y-4 text-sm">
                  <StateLine label="Incident" value={selected.content.incident?.incident_id ?? '—'} />
                  <StateLine label="Severity / status" value={`${selected.content.incident?.severity ?? '—'} / ${selected.content.incident?.status ?? '—'}`} />
                  <StateLine label="MTTR" value={selected.content.metrics?.mttr_minutes != null ? `${selected.content.metrics.mttr_minutes} min` : '—'} />
                  <p className="text-[10px] uppercase tracking-wide text-slate-500 mt-4 mb-1">Chronology</p>
                  {(selected.content.timeline || []).map((t, i) => (
                    <div key={i} className="border-l-2 border-slate-700 pl-3 py-0.5 text-xs">
                      <p className="text-slate-500">{t.timestamp || t.time || ''}</p>
                      <p className="text-slate-300">{t.description || ''}</p>
                    </div>
                  ))}
                </div>
              ) : null}

              <details className="mt-4 rounded-lg border border-slate-800 bg-slate-900/40 p-2">
                <summary className="cursor-pointer text-xs text-slate-400">Raw report JSON</summary>
                <pre className="mt-2 overflow-auto text-[10px] text-slate-400">{JSON.stringify(selected.content, null, 2)}</pre>
              </details>

              {canDelete ? (
                <button className="mt-4 rounded-lg border border-red-400/40 bg-red-500/10 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/20" onClick={() => remove(selected.report_id)}>
                  Delete report
                </button>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}