import { useEffect, useState } from 'react';
import { createRule, deleteRule, listRules, resetRules, rollbackRule, ruleHistory, testRule, toggleRule, updateRule } from '../api';
import Layout from './Layout';
import { Empty, Loading, SeverityBadge, fmtTime } from './ui';

const EMPTY_RULE = {
  rule_id: '', name: '', description: '', category: 'generic',
  enabled: true, severity: 'medium', mitre: [], config: {},
};

export default function RulesPage() {
  const [items, setItems] = useState([]);
  const [categories, setCategories] = useState({});
  const [predicates, setPredicates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(null);
  const [testing, setTesting] = useState(null);
  const [history, setHistory] = useState(null);
  const [msg, setMsg] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const res = await listRules();
      setItems(res.items || []);
      setCategories(res.categories || {});
      setPredicates(res.predicates || []);
    } catch (e) {
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3500); };

  const toggle = async (id) => {
    try {
      const r = await toggleRule(id);
      setItems((prev) => prev.map((i) => (i.rule_id === id ? { ...i, enabled: r.enabled ? 1 : 0 } : i)));
      flash(`${id} ${r.enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { flash(e.message); }
  };

  const save = async () => {
    try {
      const payload = {
        rule_id: editing.rule_id,
        name: editing.name,
        description: editing.description,
        category: editing.category,
        enabled: editing.enabled,
        severity: editing.severity,
        mitre: Array.isArray(editing.mitre) ? editing.mitre : String(editing.mitre || '').split(',').map((s) => s.trim()).filter(Boolean),
        config: typeof editing.config === 'object' ? editing.config : {},
      };
      const updated = await updateRule(payload);
      setEditing(null);
      flash(`Rule updated (v${updated.version}).`);
      load();
    } catch (e) { flash(e.message); }
  };

  const create = async () => {
    try {
      await createRule({
        rule_id: creating.rule_id,
        name: creating.name,
        description: creating.description,
        category: creating.category,
        enabled: creating.enabled,
        severity: creating.severity,
        mitre: [],
        config: typeof creating.config === 'object' ? creating.config : {},
      });
      setCreating(null);
      flash('Rule created.');
      load();
    } catch (e) { flash(e.message); }
  };

  const remove = async (r) => {
    if (!window.confirm(`Delete rule "${r.rule_id}"? This cannot be undone.`)) return;
    try {
      await deleteRule(r.rule_id);
      flash(`Deleted ${r.rule_id}.`);
      load();
    } catch (e) { flash(e.message); }
  };

  const runTest = async (id) => {
    try {
      const res = await testRule(id, { minutes: 60, limit: 500 });
      setTesting({ rule_id: id, ...res });
    } catch (e) { flash(e.message); }
  };

  const showHistory = async (id) => {
    try {
      setHistory({ rule_id: id, ...(await ruleHistory(id)) });
    } catch (e) { flash(e.message); }
  };

  const doRollback = async (version) => {
    if (!window.confirm(`Roll rule back to version ${version}?`)) return;
    try {
      await rollbackRule(history.rule_id, version);
      setHistory(null);
      flash(`Rolled back to v${version}.`);
      load();
    } catch (e) { flash(e.message); }
  };

  const reset = async () => {
    if (!window.confirm('Restore all default detection rules?')) return;
    try {
      const r = await resetRules();
      flash(`Restored ${r.restored} default rules.`);
      load();
    } catch (e) { flash(e.message); }
  };

  const editor = creating || editing;
  if (editor) {
    return (
      <Layout title={creating ? 'Create Rule' : 'Edit Rule'}>
        <button className="text-sm text-accent hover:underline mb-4" onClick={() => { setCreating(null); setEditing(null); }}>← Back to rules</button>
        <div className="panel max-w-2xl space-y-3">
          {creating ? (
            <label className="block text-sm">Predicate (rule_id)
              <select className="input mt-1 font-mono" value={editor.rule_id} onChange={(e) => setCreating({ ...creating, rule_id: e.target.value })}>
                <option value="">— choose a predicate —</option>
                {predicates.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>
          ) : null}
          <label className="block text-sm">Name
            <input className="input mt-1" value={editor.name} onChange={(e) => setEditor({ ...editor, name: e.target.value })} />
          </label>
          <label className="block text-sm">Description
            <textarea className="input mt-1" rows={2} value={editor.description} onChange={(e) => setEditor({ ...editor, description: e.target.value })} />
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="block text-sm">Category
              <select className="input mt-1" value={editor.category} onChange={(e) => setEditor({ ...editor, category: e.target.value })}>
                {Object.keys(categories).map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>
            <label className="block text-sm">Severity
              <select className="input mt-1" value={editor.severity} onChange={(e) => setEditor({ ...editor, severity: e.target.value })}>
                {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
          </div>
          <label className="block text-sm">MITRE (comma-separated)
            <input className="input mt-1" value={(editor.mitre || []).join(', ')} onChange={(e) => setEditor({ ...editor, mitre: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
          </label>
          <label className="block text-sm">Config (JSON)
            <textarea className="input mt-1 font-mono text-xs" rows={4} value={JSON.stringify(editor.config || {}, null, 2)}
              onChange={(e) => { try { setEditor({ ...editor, config: JSON.parse(e.target.value) }); } catch (_) { /* keep old on parse error */ } }} />
          </label>
          <div className="flex gap-2 pt-2">
            <button className="btn" onClick={creating ? create : save}>{creating ? 'Create Rule' : 'Save Rule'}</button>
            <button className="rounded-lg border border-slate-700 px-3 py-2 text-sm" onClick={() => { setCreating(null); setEditing(null); }}>Cancel</button>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="Detection Rules">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <p className="text-xs text-slate-400">{items.length} rules · runtime-configurable, versioned in SQLite</p>
        <button className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent hover:bg-accent/20" onClick={() => setCreating({ ...EMPTY_RULE })}>
          + Create Rule
        </button>
        <button className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-white/5" onClick={reset}>Reset to defaults</button>
      </div>
      {msg ? <div className="mb-3 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}
      {loading ? <Loading /> : items.length === 0 ? <Empty message="No rules." /> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {items.map((r) => (
            <div key={r.rule_id} className={`panel ${r.enabled ? '' : 'opacity-60'}`}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="font-semibold text-sm">{r.name}</p>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">{r.rule_id} · v{r.version ?? 1}</p>
                </div>
                <SeverityBadge severity={r.severity} />
              </div>
              <p className="mt-2 text-xs text-slate-400">{r.description}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                <span className="rounded-full border border-slate-700 px-2 py-0.5">{r.category}</span>
                {(r.mitre || []).map((m) => <span key={m} className="font-mono">{m}</span>)}
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <button className={`rounded-lg border px-3 py-1 text-xs ${r.enabled ? 'border-emerald-400/40 text-emerald-300 hover:bg-emerald-500/10' : 'border-slate-600 text-slate-300 hover:bg-white/5'}`}
                  onClick={() => toggle(r.rule_id)}>
                  {r.enabled ? 'Enabled' : 'Disabled'}
                </button>
                <button className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-white/5" onClick={() => setEditing(r)}>Edit</button>
                <button className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-white/5" onClick={() => runTest(r.rule_id)}>Test</button>
                <button className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-white/5" onClick={() => showHistory(r.rule_id)}>History</button>
                <button className="rounded-lg border border-red-400/40 px-3 py-1 text-xs text-red-300 hover:bg-red-500/10" onClick={() => remove(r)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {testing ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setTesting(null)}>
          <div className="panel max-w-xl w-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="title">Rule Test: {testing.rule_id}</h3>
              <button className="text-slate-400 hover:text-white" onClick={() => setTesting(null)}>✕</button>
            </div>
            <p className="text-sm text-slate-400">Replayed against the last 60 minutes of stored events (no effect on live detection).</p>
            <div className="mt-3 flex gap-4 text-sm">
              <div><p className="text-slate-400 text-xs uppercase">Evaluated</p><p className="text-2xl font-bold mt-1">{testing.evaluated ?? 0}</p></div>
              <div><p className="text-slate-400 text-xs uppercase">Matched</p><p className="text-2xl font-bold mt-1 text-accent">{testing.matched ?? 0}</p></div>
            </div>
            {testing.matches?.length ? (
              <div className="mt-3 max-h-60 overflow-auto space-y-1">
                {testing.matches.map((m) => (
                  <div key={m.event_id} className="rounded border border-slate-800 p-2 text-xs">
                    <span className="font-mono text-accent">{m.event_type}</span>
                    <span className="ml-2 text-slate-400">{m.ts}</span>
                    <span className="ml-2">{m.source_ip || m.host || m.username || '—'}</span>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {history ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setHistory(null)}>
          <div className="panel max-w-xl w-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="title">Version History: {history.rule_id}</h3>
              <button className="text-slate-400 hover:text-white" onClick={() => setHistory(null)}>✕</button>
            </div>
            <p className="text-sm text-slate-400 mb-3">Current version: <b className="text-accent">{history.current_version}</b>. Immutable history — every change is audited.</p>
            <div className="max-h-72 overflow-auto space-y-2">
              {(history.items || []).map((v) => (
                <div key={`${v.version}-${v.changed_at}`} className="rounded-lg border border-slate-800 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-mono">v{v.version}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-500">by {v.changed_by} · {fmtTime(v.changed_at)}</span>
                      {v.version !== history.current_version ? (
                        <button className="rounded border border-accent/40 px-2 py-0.5 text-[11px] text-accent hover:bg-accent/10"
                          onClick={() => doRollback(v.version)}>Rollback</button>
                      ) : <span className="text-[11px] text-emerald-300">current</span>}
                    </div>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">{v.change_note || (v.snapshot?.name || '')}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </Layout>
  );

  function setEditor(patch) {
    if (creating) setCreating(patch);
    else setEditing(patch);
  }
}
