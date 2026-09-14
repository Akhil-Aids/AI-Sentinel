import { useEffect, useState } from 'react';
import { createIoc, deleteIoc, getIocMatches, listIocs, updateIoc } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

const VERDICT_TONE = {
  malicious: 'text-red-300',
  suspicious: 'text-amber-300',
  unknown: 'text-slate-400',
  benign: 'text-emerald-300',
};

export default function IocPage() {
  const [items, setItems] = useState([]);
  const [iocTypes, setIocTypes] = useState([]);
  const [verdicts, setVerdicts] = useState([]);
  const [filter, setFilter] = useState({ ioc_type: '', verdict: '' });
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ ioc_type: 'ip', ioc_value: '', verdict: 'unknown', confidence: 0.8, source: 'manual', tags: '', tlp: 'WHITE', threat_actor: '', kill_chain_phase: '' });
  const [msg, setMsg] = useState('');
  const [matches, setMatches] = useState(null);
  const [editing, setEditing] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await listIocs(filter);
      setItems(res.items || []);
      setIocTypes(res.ioc_types || []);
      setVerdicts(res.verdicts || []);
    } catch (e) {
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [filter.ioc_type, filter.verdict]);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3500); };

  const add = async () => {
    if (!form.ioc_value.trim()) return;
    try {
      await createIoc({ ...form, ioc_type: form.ioc_type, tags: form.tags.split(',').map((s) => s.trim()).filter(Boolean), confidence: Number(form.confidence) || 0 });
      setForm({ ...form, ioc_value: '', tags: '' });
      flash('IOC added.');
      load();
    } catch (e) { flash(e.message); }
  };

  const saveEdit = async () => {
    try {
      await updateIoc(editing.ioc_id, {
        ...editing,
        confidence: Number(editing.confidence) || 0,
        tags: Array.isArray(editing.tags) ? editing.tags : String(editing.tags || '').split(',').map((s) => s.trim()).filter(Boolean),
      });
      setEditing(null);
      flash('IOC updated.');
      load();
    } catch (e) { flash(e.message); }
  };

  const remove = async (id, value) => {
    if (!window.confirm(`Delete IOC "${value}"?`)) return;
    try {
      await deleteIoc(id);
      flash('IOC deleted.');
      load();
    } catch (e) { flash(e.message); }
  };

  const showMatches = async (id) => {
    try {
      const m = await getIocMatches(id);
      setMatches({ ioc_id: id, items: m.items || [], count: m.count });
    } catch (e) { flash(e.message); }
  };

  const exportCsv = () => {
    window.open('/api/iocs/export?format=csv', '_blank');
  };

  return (
    <Layout title="Indicators of Compromise">
      {msg ? <div className="mb-3 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2">
          <div className="panel">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="title">IOC Registry ({items.length})</h3>
              <div className="flex gap-2">
                <select className="input !w-36" value={filter.ioc_type} onChange={(e) => setFilter({ ...filter, ioc_type: e.target.value })}>
                  <option value="">All types</option>
                  {iocTypes.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <select className="input !w-36" value={filter.verdict} onChange={(e) => setFilter({ ...filter, verdict: e.target.value })}>
                  <option value="">All verdicts</option>
                  {verdicts.map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
                <button className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-white/5" onClick={exportCsv}>Export CSV</button>
              </div>
            </div>
            {loading ? <Loading /> : items.length === 0 ? <Empty message="No IOCs registered." /> : (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="px-2 py-1.5 font-medium">Value</th>
                      <th className="px-2 py-1.5 font-medium">Type</th>
                      <th className="px-2 py-1.5 font-medium">Verdict</th>
                      <th className="px-2 py-1.5 font-medium">Confidence</th>
                      <th className="px-2 py-1.5 font-medium">TLP</th>
                      <th className="px-2 py-1.5 font-medium">Actor</th>
                      <th className="px-2 py-1.5 font-medium">Matches</th>
                      <th className="px-2 py-1.5 font-medium">Added</th>
                      <th className="px-2 py-1.5 font-medium" />
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((ioc) => (
                      <tr key={ioc.ioc_id} className="border-b border-slate-800/60">
                        <td className="px-2 py-1.5 font-mono text-accent">{ioc.ioc_value}</td>
                        <td className="px-2 py-1.5"><span className="rounded-full border border-slate-700 px-1.5 py-0.5 text-[10px] uppercase">{ioc.ioc_type}</span></td>
                        <td className={`px-2 py-1.5 uppercase ${VERDICT_TONE[ioc.verdict] || 'text-slate-400'}`}>{ioc.verdict}</td>
                        <td className="px-2 py-1.5">{(ioc.confidence * 100).toFixed(0)}%</td>
                        <td className="px-2 py-1.5">{ioc.tlp}</td>
                        <td className="px-2 py-1.5">{ioc.threat_actor || '—'}</td>
                        <td className="px-2 py-1.5">
                          <button className="text-accent hover:underline" onClick={() => showMatches(ioc.ioc_id)}>
                            {ioc.match_count ?? 0}
                          </button>
                        </td>
                        <td className="px-2 py-1.5 text-slate-500">{fmtTime(ioc.created_at)}</td>
                        <td className="px-2 py-1.5">
                          <button className="mr-1 rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-white/5" onClick={() => setEditing({ ...ioc, tags: ioc.tags || [] })}>Edit</button>
                          <button className="rounded border border-red-400/40 px-1.5 py-0.5 text-[10px] text-red-300 hover:bg-red-500/10" onClick={() => remove(ioc.ioc_id, ioc.ioc_value)}>Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="space-y-4">
          <div className="panel">
            <h3 className="title mb-3">Add IOC</h3>
            <div className="space-y-3 text-sm">
              <label className="block text-xs text-slate-400">Type
                <select className="input mt-1" value={form.ioc_type} onChange={(e) => setForm({ ...form, ioc_type: e.target.value })}>
                  {iocTypes.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Value
                <input className="input mt-1 font-mono" value={form.ioc_value} onChange={(e) => setForm({ ...form, ioc_value: e.target.value })} placeholder="203.0.113.9" />
              </label>
              <div className="grid grid-cols-2 gap-3">
                <label className="block text-xs text-slate-400">Verdict
                  <select className="input mt-1" value={form.verdict} onChange={(e) => setForm({ ...form, verdict: e.target.value })}>
                    {verdicts.map((v) => <option key={v} value={v}>{v}</option>)}
                  </select>
                </label>
                <label className="block text-xs text-slate-400">Confidence
                  <input className="input mt-1" type="number" min={0} max={1} step={0.1} value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })} />
                </label>
              </div>
              <label className="block text-xs text-slate-400">Source
                <input className="input mt-1" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
              </label>
              <label className="block text-xs text-slate-400">Tags (comma-separated)
                <input className="input mt-1" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="exfil,c2" />
              </label>
              <label className="block text-xs text-slate-400">Threat actor
                <input className="input mt-1" value={form.threat_actor} onChange={(e) => setForm({ ...form, threat_actor: e.target.value })} />
              </label>
              <button className="btn w-full" onClick={add} disabled={!form.ioc_value.trim()}>Add IOC</button>
            </div>
          </div>
        </div>
      </div>

      {editing ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setEditing(null)}>
          <div className="panel max-w-lg w-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="title">Edit IOC</h3>
              <button className="text-slate-400 hover:text-white" onClick={() => setEditing(null)}>✕</button>
            </div>
            <p className="mt-1 font-mono text-xs text-accent">{editing.ioc_value}</p>
            <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
              <label className="block text-xs text-slate-400">Verdict
                <select className="input mt-1" value={editing.verdict} onChange={(e) => setEditing({ ...editing, verdict: e.target.value })}>
                  {verdicts.map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Confidence
                <input className="input mt-1" type="number" min={0} max={1} step={0.1} value={editing.confidence} onChange={(e) => setEditing({ ...editing, confidence: e.target.value })} />
              </label>
              <label className="block text-xs text-slate-400">TLP
                <select className="input mt-1" value={editing.tlp} onChange={(e) => setEditing({ ...editing, tlp: e.target.value })}>
                  {['RED', 'AMBER', 'GREEN', 'WHITE'].map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="block text-xs text-slate-400">Tags
                <input className="input mt-1 font-mono" value={Array.isArray(editing.tags) ? editing.tags.join(', ') : (editing.tags || '')} onChange={(e) => setEditing({ ...editing, tags: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
              </label>
              <label className="block text-xs text-slate-400 col-span-2">Threat actor
                <input className="input mt-1" value={editing.threat_actor || ''} onChange={(e) => setEditing({ ...editing, threat_actor: e.target.value })} />
              </label>
            </div>
            <div className="mt-4 flex gap-2">
              <button className="btn" onClick={saveEdit}>Save</button>
              <button className="rounded-lg border border-slate-700 px-3 py-2 text-sm" onClick={() => setEditing(null)}>Cancel</button>
            </div>
          </div>
        </div>
      ) : null}

      {matches ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setMatches(null)}>
          <div className="panel max-w-2xl w-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="title">Match Records ({matches.count})</h3>
              <button className="text-slate-400 hover:text-white" onClick={() => setMatches(null)}>✕</button>
            </div>
            {matches.items.length === 0 ? <Empty message="No telemetry matches yet." /> : (
              <div className="mt-3 max-h-72 overflow-auto space-y-1">
                {matches.items.map((m) => (
                  <div key={m.match_id} className="rounded border border-slate-800 p-2 text-xs">
                    <span className="font-mono text-accent">{m.event_type || m.event_id}</span>
                    <span className="ml-2 text-slate-400">{fmtTime(m.matched_at)}</span>
                    <span className="ml-2">{m.host || ''} · {m.source_ip || ''}</span>
                    {m.alert_id ? <span className="ml-2 rounded-full border border-amber-400/40 px-1.5 py-0.5 text-[10px] text-amber-300">alerted</span> : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </Layout>
  );
}