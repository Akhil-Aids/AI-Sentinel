import { useEffect, useState } from 'react';
import { addCaseNote, getCase, getRole, listCases, listIncidents, createCase, linkIncidentToCase, updateCase } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, StatusBadge, fmtTime } from './ui';

export default function CasesPage() {
  const [cases, setCases] = useState([]);
  const [selected, setSelected] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [msg, setMsg] = useState('');
  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', category: '' });
  const [loading, setLoading] = useState(true);
  const [note, setNote] = useState('');

  const loadCases = async () => {
    setLoading(true);
    try {
      const [c, i] = await Promise.all([listCases(), listIncidents({ limit: 100 })]);
      setCases(c.items || []);
      setIncidents(i.items || []);
    } catch (e) { /* ignore */ } finally { setLoading(false); }
  };

  useEffect(() => { loadCases(); }, []);

  const loadDetail = async (id) => {
    try {
      const c = await getCase(id);
      setSelected(c);
    } catch (e) { /* ignore */ }
  };

  useEffect(() => {
    if (selected && !loading) loadDetail(selected.case_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.case_id]);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const doCreate = async () => {
    if (form.title.length < 3) { flash('Title required (3+ chars).'); return; }
    try {
      const c = await createCase(form);
      flash(`Case ${c.case_id} created.`);
      setForm({ title: '', description: '', severity: 'medium', category: '' });
      loadCases();
      loadDetail(c.case_id);
    } catch (e) { flash(e.message); }
  };

  const setStatus = async (id, status) => {
    try {
      await updateCase(id, { status });
      flash(`Case → ${status}.`);
      loadCases();
      if (selected?.case_id === id) loadDetail(id);
    } catch (e) { flash(e.message); }
  };

  const linkIncident = async (incidentId) => {
    try {
      await linkIncidentToCase(selected.case_id, incidentId);
      flash('Incident linked.');
      loadDetail(selected.case_id);
    } catch (e) { flash(e.message); }
  };

  const doNote = async () => {
    if (!note.trim()) return;
    try {
      await addCaseNote(selected.case_id, note);
      setNote('');
      loadDetail(selected.case_id);
    } catch (e) { flash(e.message); }
  };

  if (loading) return <Layout title="Cases"><Loading /></Layout>;

  const linkedIds = new Set((selected?.incidents || []).map((i) => i.incident_id));

  return (
    <Layout title="Case Management">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-1">
          <div className="panel mb-4">
            <h3 className="title mb-3">New Case</h3>
            <div className="space-y-2">
              <input className="input" placeholder="Title*" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
              <input className="input" placeholder="Category (e.g. credential-attack)" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} />
              <textarea className="input" rows="3" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <button className="btn w-full" onClick={doCreate}>Create Case</button>
            </div>
          </div>
          <div className="panel">
            <h3 className="title mb-3">Cases</h3>
            {cases.length === 0 ? <Empty message="No cases yet." /> : (
              <div className="max-h-96 space-y-2 overflow-auto">
                {cases.map((c) => (
                  <button key={c.case_id} onClick={() => loadDetail(c.case_id)}
                    className={`w-full rounded-lg border p-2 text-left text-sm ${selected?.case_id === c.case_id ? 'border-accent/50 bg-accent/10' : 'border-slate-800 hover:bg-white/5'}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-medium">{c.title}</span>
                      <StatusBadge status={c.status} />
                    </div>
                    <div className="mt-1 flex items-center justify-between text-[11px] text-slate-500">
                      <span className="font-mono">{c.case_id}</span>
                      <SeverityBadge severity={c.severity} />
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="lg:col-span-2">
          {!selected ? <div className="panel"><Empty message="Select a case to inspect it." /></div> : (
            <>
              <div className="panel mb-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-lg font-bold">{selected.title}</h3>
                    <p className="mt-1 text-xs text-slate-500">
                      <span className="font-mono">{selected.case_id}</span> · {selected.category || 'uncategorised'} · created {fmtTime(selected.created_at)}
                    </p>
                  </div>
                  <StatusBadge status={selected.status} />
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {getRole() === 'ADMIN' || getRole() === 'SECURITY_ENGINEER' ? (
                    <>
                      {['INVESTIGATING', 'CLOSED'].map((s) => (
                        <button key={s} className="rounded border border-slate-700 px-2 py-1 text-[11px] text-slate-300"
                          onClick={() => setStatus(selected.case_id, s)}>Set {s}</button>
                      ))}
                      {selected.status === 'CLOSED' ? (
                        <button className="rounded border border-emerald-400/40 px-2 py-1 text-[11px] text-emerald-300"
                          onClick={() => setStatus(selected.case_id, 'OPEN')}>Reopen</button>
                      ) : null}
                    </>
                  ) : null}
                </div>
                {selected.description ? <p className="mt-3 text-sm text-slate-300">{selected.description}</p> : null}
                {selected.resolution ? (
                  <div className="mt-3 rounded-lg border border-emerald-400/30 bg-emerald-500/10 p-2 text-xs text-emerald-300">
                    <b>Resolution:</b> {selected.resolution}
                  </div>
                ) : null}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="panel">
                  <h3 className="title mb-3">Linked Incidents ({selected.incidents?.length || 0})</h3>
                  {!selected.incidents?.length ? <Empty message="No incidents linked." /> : (
                    <div className="space-y-2 max-h-52 overflow-auto">
                      {selected.incidents.map((i) => (
                        <div key={i.incident_id} className="rounded-lg border border-slate-800 p-2 text-xs">
                          <div className="flex items-center justify-between gap-2">
                            <a href={`/incidents/${i.incident_id}`} className="text-accent hover:underline"
                              onClick={(e) => { e.preventDefault(); window.history.pushState({}, '', `/incidents/${i.incident_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }}>
                              {i.title}
                            </a>
                            <StatusBadge status={i.status} />
                          </div>
                          <p className="mt-1 font-mono text-[10px] text-slate-500">{i.incident_id} · {fmtTime(i.created_at)}</p>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="mt-3">
                    <label className="text-[11px] uppercase text-slate-500">Link incident</label>
                    <select className="input mt-1" onChange={(e) => e.target.value && linkIncident(e.target.value)} defaultValue="">
                      <option value="" disabled>Select incident…</option>
                      {incidents.filter((i) => !linkedIds.has(i.incident_id)).map((i) => (
                        <option key={i.incident_id} value={i.incident_id}>{i.title} ({i.incident_id})</option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="panel">
                  <h3 className="title mb-3">Linked Evidence ({selected.evidence?.length || 0})</h3>
                  {!selected.evidence?.length ? <Empty message="No evidence attached." /> : (
                    <div className="space-y-2 max-h-52 overflow-auto">
                      {selected.evidence.map((e) => (
                        <div key={e.evidence_id} className="rounded-lg border border-slate-800 p-2 text-xs">
                          <p className="font-mono text-accent">{e.evidence_id}</p>
                          <p className="truncate text-slate-300">{e.title}</p>
                          <p className="text-[10px] uppercase text-slate-500">{e.type} · {e.integrity_status}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="panel">
                <h3 className="title mb-3">Notes ({selected.notes?.length || 0})</h3>
                <div className="mb-3 flex gap-2">
                  <input className="input flex-1" placeholder="Add a note…" value={note} onChange={(e) => setNote(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && doNote()} />
                  <button className="btn" onClick={doNote}>Add</button>
                </div>
                {!selected.notes?.length ? <Empty message="No notes." /> : (
                  <div className="max-h-56 space-y-2 overflow-auto">
                    {selected.notes.map((n) => (
                      <div key={n.id} className="rounded-lg border border-slate-800 p-2 text-sm">
                        <p className="text-slate-200">{n.note}</p>
                        <p className="mt-1 text-[10px] text-slate-500">{n.created_by} · {fmtTime(n.created_at)}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </Layout>
  );
}