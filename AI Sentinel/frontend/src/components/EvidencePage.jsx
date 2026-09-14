import { useEffect, useState } from 'react';
import { createEvidence, listCases, listEvidence, listIncidents, verifyEvidence } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

const INTEGRITY_STYLES = {
  VERIFIED: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  PENDING: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  TAMPERED: 'bg-red-500/15 text-red-300 border-red-400/40',
  NOT_APPLICABLE: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
};

export default function EvidencePage() {
  const [items, setItems] = useState([]);
  const [cases, setCases] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [msg, setMsg] = useState('');
  const [form, setForm] = useState({ type: 'artifact', title: '', description: '', source: '', content: '', content_hash: '', incident_id: '', case_id: '' });
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [e, c, i] = await Promise.all([listEvidence({ limit: 100 }), listCases(), listIncidents({ limit: 100 })]);
      setItems(e.items || []);
      setCases(c.items || []);
      setIncidents(i.items || []);
    } catch (err) { /* ignore */ } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const doCreate = async () => {
    if (form.title.length < 1) { flash('Title required.'); return; }
    if (!form.incident_id && !form.case_id) { flash('Attach evidence to an incident or case.'); return; }
    try {
      const ev = await createEvidence(form);
      flash(`Evidence ${ev.evidence_id} stored (${ev.integrity_status}).`);
      setForm({ type: 'artifact', title: '', description: '', source: '', content: '', content_hash: '', incident_id: '', case_id: '' });
      load();
    } catch (e) { flash(e.message); }
  };

  const doVerify = async (id) => {
    try {
      const r = await verifyEvidence(id);
      flash(`Re-verified: ${r.integrity_status}.`);
      load();
    } catch (e) { flash(e.message); }
  };

  if (loading) return <Layout title="Evidence"><Loading /></Layout>;

  return (
    <Layout title="Evidence Vault">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="panel mb-4">
        <h3 className="title mb-3">Capture Evidence</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <input className="input" placeholder="Title*" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <select className="input" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
            {['artifact', 'log', 'packet', 'file', 'process', 'url', 'domain', 'ip', 'memory', 'registry', 'screenshot', 'other'].map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input" placeholder="Source (tool/path)" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
          <select className="input" value={form.incident_id} onChange={(e) => setForm({ ...form, incident_id: e.target.value })}>
            <option value="">Attach to incident…</option>
            {incidents.map((i) => <option key={i.incident_id} value={i.incident_id}>{i.title}</option>)}
          </select>
          <select className="input" value={form.case_id} onChange={(e) => setForm({ ...form, case_id: e.target.value })}>
            <option value="">Attach to case…</option>
            {cases.map((c) => <option key={c.case_id} value={c.case_id}>{c.title}</option>)}
          </select>
          <input className="input" placeholder="External content hash (optional)" value={form.content_hash} onChange={(e) => setForm({ ...form, content_hash: e.target.value })} />
        </div>
        <div className="mt-2 grid grid-cols-1 gap-2">
          <input className="input" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <textarea className="input" rows="3" placeholder="Raw content / artifact text (hashed at rest)" value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} />
        </div>
        <button className="btn mt-2" onClick={doCreate}>Store Evidence</button>
      </div>

      <div className="panel">
        <h3 className="title mb-3">Evidence Records ({items.length})</h3>
        {items.length === 0 ? <Empty message="No evidence captured yet. Everything is immutably stored with a SHA-256 digest." /> : (
          <div className="max-h-[30rem] overflow-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Evidence</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Ref</th>
                  <th className="pb-2">Hash</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Created</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.evidence_id} className="border-t border-slate-800">
                    <td className="py-1.5">
                      <p className="font-mono text-accent">{e.evidence_id}</p>
                      <p className="text-slate-300">{e.title}</p>
                    </td>
                    <td className="py-1.5 uppercase text-slate-400">{e.type}</td>
                    <td className="py-1.5 font-mono text-[10px] text-slate-500">{e.incident_id || e.case_id || '—'}</td>
                    <td className="py-1.5 font-mono text-[10px] text-slate-500">{e.content_hash ? e.content_hash.slice(0, 12) : '—'}</td>
                    <td className="py-1.5">
                      <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] uppercase ${INTEGRITY_STYLES[e.integrity_status] || INTEGRITY_STYLES.NOT_APPLICABLE}`}>{e.integrity_status}</span>
                    </td>
                    <td className="py-1.5 text-[10px] text-slate-500">{fmtTime(e.created_at)}</td>
                    <td className="py-1.5 text-right">
                      <button className="rounded border border-slate-700 px-2 py-1 text-[11px] text-slate-300" onClick={() => doVerify(e.evidence_id)}>Re-verify</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}