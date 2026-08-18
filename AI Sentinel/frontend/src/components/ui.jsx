export const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

export function severityStyles(severity) {
  switch (severity) {
    case 'critical':
      return 'bg-red-500/15 text-red-300 border-red-400/40';
    case 'high':
      return 'bg-rose-500/15 text-rose-300 border-rose-400/40';
    case 'medium':
      return 'bg-amber-500/15 text-amber-300 border-amber-400/40';
    case 'low':
      return 'bg-sky-500/15 text-sky-300 border-sky-400/40';
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-400/40';
  }
}

export function riskStyles(level) {
  switch ((level || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'text-red-400';
    case 'medium':
    case 'elevated':
      return 'text-amber-300';
    default:
      return 'text-emerald-300';
  }
}

export function SeverityBadge({ severity }) {
  return (
    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] uppercase tracking-wide ${severityStyles(severity)}`}>
      {severity || 'unknown'}
    </span>
  );
}

export function StatusBadge({ status }) {
  const map = {
    NEW: 'bg-red-500/15 text-red-300 border-red-400/40',
    INVESTIGATING: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
    CONTAINED: 'bg-sky-500/15 text-sky-300 border-sky-400/40',
    RESOLVED: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
    FALSE_POSITIVE: 'bg-slate-500/15 text-slate-300 border-slate-400/40',
  };
  return (
    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] uppercase tracking-wide ${map[status] || map.NEW}`}>
      {status || 'NEW'}
    </span>
  );
}

export function Kpi({ label, value, sub, tone = 'accent' }) {
  const tones = {
    accent: 'text-accent',
    danger: 'text-danger',
    warn: 'text-warn',
    emerald: 'text-emerald-300',
    sky: 'text-sky-300',
  };
  return (
    <div className="panel">
      <p className="label">{label}</p>
      <p className={`value ${tones[tone] || tones.accent}`}>{value}</p>
      {sub ? <p className="text-xs text-slate-400 mt-1">{sub}</p> : null}
    </div>
  );
}

export function Panel({ title, children, className = '' }) {
  return (
    <div className={`panel ${className}`}>
      {title ? <h3 className="title mb-3">{title}</h3> : null}
      {children}
    </div>
  );
}

export function Empty({ message = 'No data yet.' }) {
  return <p className="text-sm text-slate-500 py-6 text-center">{message}</p>;
}

export function Loading({ label = 'Loading…' }) {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-slate-700 border-t-accent" />
      <span className="ml-3 text-sm text-slate-400">{label}</span>
    </div>
  );
}

export function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
