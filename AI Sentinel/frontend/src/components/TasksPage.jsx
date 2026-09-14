import { useEffect, useState } from 'react';
import { createTask, listCases, listIncidents, listTasks, updateTask } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

const TASK_STYLES = {
  TODO: 'bg-red-500/15 text-red-300 border-red-400/40',
  IN_PROGRESS: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  DONE: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  CANCELLED: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
};

export default function TasksPage() {
  const [tasks, setTasks] = useState([]);
  const [cases, setCases] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [filter, setFilter] = useState('');
  const [msg, setMsg] = useState('');
  const [form, setForm] = useState({ title: '', description: '', owner: '', priority: 'medium', incident_id: '', case_id: '' });
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [t, c, i] = await Promise.all([listTasks({ status: filter || undefined }), listCases(), listIncidents({ limit: 100 })]);
      setTasks(t.items || []);
      setCases(c.items || []);
      setIncidents(i.items || []);
    } catch (e) { /* ignore */ } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [filter]);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const doCreate = async () => {
    if (form.title.length < 3) { flash('Title required (3+ chars).'); return; }
    try {
      const t = await createTask(form);
      flash(`Task ${t.task_id} created.`);
      setForm({ title: '', description: '', owner: '', priority: 'medium', incident_id: '', case_id: '' });
      load();
    } catch (e) { flash(e.message); }
  };

  const setStatus = async (id, status) => {
    try {
      await updateTask(id, { status });
      load();
    } catch (e) { flash(e.message); }
  };

  if (loading) return <Layout title="SOC Tasks"><Loading /></Layout>;

  return (
    <Layout title="SOC Tasks">
      {msg ? <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="panel mb-4">
        <h3 className="title mb-3">New Task</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
          <input className="input" placeholder="Title*" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <input className="input" placeholder="Owner" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          <select className="input" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
            {['low', 'medium', 'high', 'critical'].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className="btn" onClick={doCreate}>Create Task</button>
        </div>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-2">
          <input className="input md:col-span-2" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <select className="input" value={form.incident_id} onChange={(e) => setForm({ ...form, incident_id: e.target.value })}>
            <option value="">Incident…</option>
            {incidents.map((i) => <option key={i.incident_id} value={i.incident_id}>{i.title}</option>)}
          </select>
        </div>
        <div className="mt-2">
          <select className="input w-full md:w-1/3" value={form.case_id} onChange={(e) => setForm({ ...form, case_id: e.target.value })}>
            <option value="">Case…</option>
            {cases.map((c) => <option key={c.case_id} value={c.case_id}>{c.title}</option>)}
          </select>
        </div>
      </div>

      <div className="flex gap-2 mb-4">
        {['', 'TODO', 'IN_PROGRESS', 'DONE', 'CANCELLED'].map((s) => (
          <button key={s} onClick={() => setFilter(s)}
            className={`rounded-lg border px-3 py-1.5 text-xs ${filter === s ? 'border-accent/50 bg-accent/15 text-accent' : 'border-slate-700 text-slate-300 hover:bg-white/5'}`}>
            {s || 'All'}
          </button>
        ))}
      </div>

      <div className="panel">
        <h3 className="title mb-3">Tasks ({tasks.length})</h3>
        {tasks.length === 0 ? <Empty message="No tasks match this view." /> : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Task</th>
                  <th className="pb-2">Priority</th>
                  <th className="pb-2">Owner</th>
                  <th className="pb-2">Ref</th>
                  <th className="pb-2">Due</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Change</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map((t) => (
                  <tr key={t.task_id} className="border-t border-slate-800">
                    <td className="py-1.5">
                      <p className="font-medium text-slate-200">{t.title}</p>
                      <p className="font-mono text-[10px] text-slate-500">{t.task_id}</p>
                    </td>
                    <td className="py-1.5 uppercase text-slate-400">{t.priority}</td>
                    <td className="py-1.5 text-slate-400">{t.owner || '—'}</td>
                    <td className="py-1.5 font-mono text-[10px] text-slate-500">{t.incident_id || t.case_id || '—'}</td>
                    <td className="py-1.5 text-[10px] text-slate-500">{fmtTime(t.due_at)}</td>
                    <td className="py-1.5">
                      <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] uppercase ${TASK_STYLES[t.status] || TASK_STYLES.TODO}`}>{t.status}</span>
                    </td>
                    <td className="py-1.5">
                      {t.status === 'TODO' ? (
                        <button className="rounded border border-slate-700 px-2 py-1 text-[11px]" onClick={() => setStatus(t.task_id, 'IN_PROGRESS')}>Start</button>
                      ) : t.status === 'IN_PROGRESS' ? (
                        <span className="flex gap-1">
                          <button className="rounded border border-emerald-400/40 px-2 py-1 text-[11px] text-emerald-300" onClick={() => setStatus(t.task_id, 'DONE')}>Done</button>
                          <button className="rounded border border-slate-700 px-2 py-1 text-[11px]" onClick={() => setStatus(t.task_id, 'TODO')}>Back</button>
                        </span>
                      ) : (
                        <button className="rounded border border-slate-700 px-2 py-1 text-[11px]" onClick={() => setStatus(t.task_id, 'IN_PROGRESS')}>Reopen</button>
                      )}
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