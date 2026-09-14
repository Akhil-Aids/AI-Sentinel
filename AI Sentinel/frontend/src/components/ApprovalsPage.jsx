import { useEffect, useState } from 'react';
import { approveApproval, denyApproval, listApprovals } from '../api';
import Layout from './Layout';
import { Empty, Loading, fmtTime } from './ui';

const STATUS_TONE = {
  PENDING: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  APPROVED: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  DENIED: 'bg-red-500/15 text-red-300 border-red-400/40',
};

const ACTION_TONE = {
  BLOCK_IP: 'border-red-400/40 bg-red-500/10 text-red-300',
  ISOLATE_ENDPOINT: 'border-red-400/40 bg-red-500/10 text-red-300',
};

export default function ApprovalsPage() {
  const [tab, setTab] = useState('PENDING');
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState('');
  const [note, setNote] = useState({});

  const load = async () => {
    setLoading(true);
    try {
      const res = await listApprovals(tab === 'ALL' ? '' : tab, 200);
      setItems(res.items || []);
    } catch (e) {
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [tab]);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3500); };

  const decide = async (id, approve) => {
    if (!window.confirm(`${approve ? 'Approve' : 'Deny'} this response action?`)) return;
    try {
      if (approve) await approveApproval(id, note[id] || 'Approved in console');
      else await denyApproval(id, note[id] || 'Denied in console');
      flash(`${approve ? 'Approved' : 'Denied'} ${id}.`);
      load();
    } catch (e) { flash(e.message); }
  };

  return (
    <Layout title="Approval Center">
      <p className="mb-4 text-xs text-slate-400">
        Two-person rule enforcement: destructive response actions against high-severity incidents are held until a
        Security Engineer (or higher) approves or denies them. Every decision is audited.
      </p>
      {msg ? <div className="mb-3 rounded-lg border border-accent/30 bg-accent/10 p-3 text-sm">{msg}</div> : null}

      <div className="mb-4 flex gap-2">
        {['PENDING', 'APPROVED', 'DENIED', 'ALL'].map((t) => (
          <button key={t} className={`rounded-lg border px-3 py-1.5 text-xs ${tab === t ? 'border-accent/50 bg-accent/15 text-accent' : 'border-slate-700 text-slate-300 hover:bg-white/5'}`}
            onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>

      {loading ? <Loading /> : items.length === 0 ? <Empty message="No approvals here." /> : (
        <div className="space-y-2">
          {items.map((a) => (
            <div key={a.approval_id} className="panel">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`rounded-full border px-2 py-0.5 text-[11px] uppercase ${ACTION_TONE[a.action_type] || 'border-slate-700 text-slate-300'}`}>{a.action_type}</span>
                    <span className={`rounded-full border px-2 py-0.5 text-[11px] uppercase ${STATUS_TONE[a.status] || STATUS_TONE.PENDING}`}>{a.status}</span>
                  </div>
                  <p className="mt-1.5 text-sm text-slate-300">{a.reason || 'No justification provided'}</p>
                  <p className="mt-1 text-[11px] text-slate-500">
                    {a.incident_title ? (<span className="text-slate-300">{a.incident_title} — </span>) : null}
                    <span className="font-mono">{a.incident_id}</span> · requested by {a.requested_by} · {fmtTime(a.created_at)}
                    {a.resolved_at ? ` · decided by ${a.approved_by || '—'} · ${fmtTime(a.resolved_at)}` : ''}
                  </p>
                </div>
                {a.status === 'PENDING' ? (
                  <div className="flex flex-col items-end gap-2">
                    <input className="input w-72" placeholder="Decision note (optional)" value={note[a.approval_id] || ''}
                      onChange={(e) => setNote({ ...note, [a.approval_id]: e.target.value })} />
                    <div className="flex gap-2">
                      <button className="rounded-lg border border-emerald-400/40 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/20" onClick={() => decide(a.approval_id, true)}>Approve</button>
                      <button className="rounded-lg border border-red-400/40 bg-red-500/10 px-3 py-1 text-xs text-red-300 hover:bg-red-500/20" onClick={() => decide(a.approval_id, false)}>Deny</button>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}