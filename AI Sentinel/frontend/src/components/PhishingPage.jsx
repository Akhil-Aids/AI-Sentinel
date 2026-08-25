import { useEffect, useState } from 'react';
import { analyzePhishing, listPhishingScans } from '../api';
import Layout from './Layout';
import { Empty, fmtTime } from './ui';

const VERDICT_STYLES = {
  MALICIOUS: 'bg-red-500/15 text-red-300 border-red-400/40',
  SUSPICIOUS: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  SAFE: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  ERROR: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
  UNKNOWN: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
};

function validateUrl(value) {
  const v = value.trim();
  if (!v) return 'Please enter a URL.';
  const hasScheme = /^https?:\/\//i.test(v);
  if (hasScheme) {
    try {
      const parsed = new URL(v);
      if (!parsed.hostname || !parsed.hostname.includes('.')) return 'Invalid URL format. Please enter a valid URL.';
      return null;
    } catch { return 'Invalid URL format. Please enter a valid URL.'; }
  }
  if (/\s/.test(v) && !v.startsWith('http')) return 'Invalid URL format. Please enter a valid URL.';
  const candidate = v.split('/')[0].split('?')[0].split('#')[0];
  if (candidate.includes('.') && /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(candidate)) return null;
  return 'Invalid URL format. Please enter a valid URL.';
}

export default function PhishingPage() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [scans, setScans] = useState([]);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const loadScans = async () => {
    try {
      const res = await listPhishingScans();
      setScans(res.items || []);
    } catch (e) { /* ignore */ }
  };

  useEffect(() => { loadScans(); }, []);

  const analyze = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    const validationError = validateUrl(url);
    if (validationError) {
      setMsg(validationError);
      setResult(null);
      return;
    }
    setBusy(true);
    setMsg('');
    try {
      const r = await analyzePhishing(url.trim());
      setResult(r);
      loadScans();
    } catch (err) {
      setMsg(err.message);
    } finally {
      setBusy(false);
    }
  };

  const verdict = result ? (VERDICT_STYLES[result.verdict] || VERDICT_STYLES.SAFE) : '';

  return (
    <Layout title="Phishing Analysis">
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="panel">
          <h3 className="title mb-2">Analyze a URL</h3>
          <p className="text-xs text-slate-400 mb-3">Offline analysis — never fetches the URL. Uses heuristic indicators + local threat intelligence.</p>
          <form onSubmit={analyze} className="flex gap-2">
            <input className="input" placeholder="https://suspicious.example.com/login" value={url}
              onChange={(e) => setUrl(e.target.value)} />
            <button className="btn shrink-0" disabled={busy}>{busy ? '…' : 'Analyze'}</button>
          </form>
          {msg ? <p className="mt-3 text-sm text-red-300">{msg}</p> : null}

          {result ? (
            <div className={`mt-4 rounded-lg border p-4 ${verdict}`}>
              <p className="text-xs uppercase tracking-wide">{result.verdict}</p>
              <p className="text-2xl font-bold mt-1">{result.verdict}</p>
              <p className="text-sm mt-2 break-all font-mono text-xs">{result.url}</p>
              <div className="mt-3 grid grid-cols-3 gap-2 text-sm">
                <div><p className="text-xs text-slate-400">Risk</p><p className="font-semibold">{result.risk_score}/100</p></div>
                <div><p className="text-xs text-slate-400">Confidence</p><p className="font-semibold">{Math.round((result.confidence || 0) * 100)}%</p></div>
                <div><p className="text-xs text-slate-400">Host</p><p className="font-mono text-xs break-all">{result.host}</p></div>
              </div>
              <div className="mt-3">
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Reasons</p>
                <ul className="list-disc pl-4 space-y-1 text-sm">
                  {(result.reasons || []).map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
              {(result.indicators || []).length ? (
                <div className="mt-3">
                  <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Indicators (IOC)</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(result.indicators || []).map((ioc) => (
                      <span key={ioc} className="rounded-full border border-slate-700 px-2 py-0.5 text-[11px] font-mono text-slate-300">{ioc}</span>
                    ))}
                  </div>
                </div>
              ) : null}
              {result.scan_id ? (
                <p className="mt-3 text-[11px] text-slate-400">scan {result.scan_id} · scanner {result.scanner_ip || '—'} · {fmtTime(result.created_at)}</p>
              ) : null}
            </div>
          ) : null}
        </div>

        <div className="panel">
          <h3 className="title mb-3">Scan History</h3>
          {scans.length === 0 ? <Empty message="No scans yet." /> : (
            <div className="space-y-2 max-h-[480px] overflow-auto">
              {scans.map((s) => (
                <div key={s.scan_id} className="rounded-lg border border-slate-800 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] uppercase ${VERDICT_STYLES[s.verdict] || VERDICT_STYLES.SAFE}`}>{s.verdict}</span>
                    <span className="text-xs text-slate-500">{fmtTime(s.created_at)}</span>
                  </div>
                  <p className="mt-2 font-mono text-xs break-all">{s.url}</p>
                  <p className="mt-1 text-xs text-slate-400">risk {s.risk_score} · scanner {s.scanner_ip || '—'}</p>
                  {s.reasons?.length ? (
                    <ul className="mt-1 list-disc pl-4 text-[11px] text-slate-400">
                      {(s.reasons || []).slice(0, 4).map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  ) : null}
                  {s.incident_id ? (
                    <a href={`/incidents/${s.incident_id}`} className="mt-2 inline-block text-xs text-accent hover:underline"
                      onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', `/incidents/${s.incident_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }}>
                      → Linked incident {s.incident_id}
                    </a>
                  ) : null}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
