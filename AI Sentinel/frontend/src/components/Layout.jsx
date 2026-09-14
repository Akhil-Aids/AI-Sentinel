import { useEffect, useState } from 'react';
import { getRole, globalSearch, listNotifications, markAllNotificationsRead, unreadNotifications, logout } from '../api';
import { useLiveSocket } from '../useLiveSocket';

const NAV = [
  { to: '/', label: 'Overview', icon: 'M3 12l9-9 9 9M5 10v10h5v-6h4v6h5V10', end: true },
  { to: '/events', label: 'Live Events', icon: 'M13 5l7 7-7 7M5 5l7 7-7 7' },
  { to: '/alerts', label: 'Alerts', icon: 'M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/incidents', label: 'Incidents', icon: 'M9 12h6m-6 4h6M9 8h6M5 3h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z' },
  { to: '/hunts', label: 'Threat Hunting', icon: 'M16 12a4 4 0 11-8 0 4 4 0 018 0zM2.5 12s3.5-7 9.5-7 9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7z' },
  { to: '/iocs', label: 'IOC Registry', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4' },
  { to: '/hosts', label: 'Hosts', icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4' },
  { to: '/network', label: 'Network', icon: 'M8 9l-5 5 5-5M16 9l5 5-5 5M13 4l-2 16' },
  { to: '/approvals', label: 'Approvals', icon: 'M10 14l2-2m0 0l2-2m-2 2l2 2m-2-2l-2 2m4-8V4a2 2 0 00-2-2H9a2 2 0 00-2 2v2m-1 0h12a2 2 0 012 2v10a2 2 0 01-2 2H6a2 2 0 01-2-2V8a2 2 0 012-2z' },
  { to: '/cases', label: 'Cases', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2 2v0' },
  { to: '/evidence', label: 'Evidence', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2' },
  { to: '/tasks', label: 'SOC Tasks', icon: 'M4 4h16a2 2 0 012 2v12a2 2 0 01-2 2H4a2 2 0 01-2-2V6a2 2 0 012-2zM16 9l-4 4m0-4l4 4' },
  { to: '/rules', label: 'Detection Rules', icon: 'M12 3v3m6.4-1.4l-2.1 2.1M21 12h-3m1.4 6.4l-2.1-2.1M12 21v-3m-6.4 1.4l2.1-2.1M3 12h3m-1.4-6.4l2.1 2.1M9 16a4 4 0 116 0' },
  { to: '/phishing', label: 'Phishing Analysis', icon: 'M13 6a2 2 0 11-4 0 2 2 0 014 0zM8 10h8l-1 10H9L8 10z' },
  { to: '/sla', label: 'SLA', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/mitre', label: 'MITRE', icon: 'M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z' },
  { to: '/posture', label: 'Posture', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/data-quality', label: 'Data Quality', icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4' },
  { to: '/assistant', label: 'AI Assistant', icon: 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/reports', label: 'Reports', icon: 'M9 17v-2m3 2v-4m3 4v-6M4 4h16a2 2 0 012 2v12a2 2 0 01-2 2H4a2 2 0 01-2-2V6a2 2 0 012-2z' },
  { to: '/system', label: 'System', icon: 'M10.3 4.2l1-1a1 1 0 011.4 0l1 1A3 3 0 0115 4h1a1 1 0 011 1v1a3 3 0 001.8 2.7l1 .6a1 1 0 010 1.4l-1 1a3 3 0 00-1 2.2v1a1 1 0 01-1 1h-1a3 3 0 01-2.7-1.8l-.6-1a1 1 0 00-1.4 0l-1 1A3 3 0 017 16h-1a1 1 0 01-1-1v-1a3 3 0 00-1.8-2.7l-1-.6a1 1 0 010-1.4l1-1A3 3 0 004 6V5a1 1 0 011-1h1a3 3 0 002.3-1.8z' },
];

const WS_LABEL = {
  connecting: { text: 'Connecting', cls: 'bg-amber-400 animate-pulse' },
  connected: { text: 'Live', cls: 'bg-emerald-400' },
  reconnecting: { text: 'Reconnecting', cls: 'bg-amber-400 animate-pulse' },
  disconnected: { text: 'Offline', cls: 'bg-red-400' },
};

function NavLink({ item, location }) {
  const active = item.end ? location.pathname === item.to : location.pathname.startsWith(item.to);
  return (
    <a
      href={item.to}
      className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
        active ? 'bg-accent/15 text-accent border border-accent/30' : 'text-slate-300 hover:bg-white/5'
      }`}
      onClick={(e) => {
        e.preventDefault();
        if (typeof window !== 'undefined') window.history.pushState({}, '', item.to);
        window.dispatchEvent(new PopStateEvent('popstate'));
      }}
    >
      <svg className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
      </svg>
      {item.label}
    </a>
  );
}

const SEARCH_LABELS = {
  events: 'Events', alerts: 'Alerts', incidents: 'Incidents', hosts: 'Hosts', iocs: 'IOCs', users: 'Users',
};

function GlobalSearch() {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState(null);
  const [tick, setTick] = useState(0);

  const navigate = (path) => {
    if (typeof window !== 'undefined') window.history.pushState({}, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
    setOpen(false);
  };

  useEffect(() => {
    if (q.trim().length < 2) { setResult(null); return; }
    const timer = setTimeout(async () => {
      try {
        const res = await globalSearch(q, 4);
        setResult(res.status === 'OK' ? res : null);
      } catch (e) {
        setResult(null);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [q, tick]);

  const renderItem = (group, item) => {
    switch (group) {
      case 'events':
        return <span><b className="text-accent">{item.event_type}</b> <span className="text-slate-500">{item.host || ''}</span></span>;
      case 'alerts':
        return <span>{item.title} <span className="text-slate-500">{item.severity}</span></span>;
      case 'incidents':
        return <span><b>{item.title}</b> <span className="text-slate-500">{item.status}</span></span>;
      case 'hosts':
        return <span>{item.hostname} <span className="text-slate-500">{item.ip}</span></span>;
      case 'iocs':
        return <span className="font-mono text-accent">{item.ioc_value} <span className="text-slate-500">{item.ioc_type}</span></span>;
      default:
        return <span>{item.full_name || item.username}</span>;
    }
  };

  const total = result ? Object.values(result.groups || {}).reduce((n, a) => n + a.length, 0) : 0;

  return (
    <div className="relative mb-4">
      {open && result ? (
        <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
      ) : null}
      <div className="relative z-30">
        <input
          className="input w-full pr-8"
          placeholder="Search events, alerts, incidents, IOCs…"
          value={q}
          onChange={(e) => { setQ(e.target.value); setOpen(true); setTick((t) => t + 1); }}
          onFocus={() => setOpen(true)}
        />
        {q ? (
          <button className="absolute right-2 top-2.5 text-slate-500 hover:text-white" onClick={() => { setQ(''); setResult(null); setOpen(false); }}>✕</button>
        ) : null}
      </div>
      {open && q.trim().length >= 2 && result ? (
        <div className="absolute left-0 right-0 top-full z-30 mt-1 rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
          {total === 0 ? <p className="p-3 text-sm text-slate-500">No matches.</p> : (
            <div className="max-h-96 overflow-auto p-2">
              <p className="px-2 py-1 text-[10px] uppercase tracking-wide text-slate-500">{total} match(es)</p>
              {Object.keys(SEARCH_LABELS).map((group) => {
                const items = (result.groups || {})[group] || [];
                if (items.length === 0) return null;
                return (
                  <div key={group} className="mt-1">
                    <p className="px-2 text-[10px] uppercase tracking-wide text-slate-400">{SEARCH_LABELS[group]}</p>
                    {items.map((item, i) => (
                      <a key={i} href="#" onClick={(e) => { e.preventDefault(); navigate(`/search?q=${encodeURIComponent(q)}`); }}
                        className="flex items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-xs text-slate-200 hover:bg-white/5">
                        <span className="truncate">{renderItem(group, item)}</span>
                        <span className="text-[9px] uppercase text-slate-600">{item[group === 'hosts' ? 'hostname' : 'id'] || ''}</span>
                      </a>
                    ))}
                  </div>
                );
              })}
              <a href="#" onClick={(e) => { e.preventDefault(); navigate(`/search?q=${encodeURIComponent(q)}`); }}
                className="mt-1 block rounded-lg border-t border-slate-800 px-2 py-2 text-center text-xs text-accent hover:bg-white/5">
                View all results →
              </a>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}

function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [items, setItems] = useState([]);

  const refresh = async () => {
    try {
      const [u, list] = await Promise.all([unreadNotifications(), listNotifications()]);
      setUnread(u.unread || 0);
      setItems(list.items || []);
    } catch (e) { /* console stays quiet; badge shows 0 */ }
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 20000);
    window.addEventListener('focus', refresh);
    return () => { clearInterval(id); window.removeEventListener('focus', refresh); };
  }, []);

  const readAll = async () => {
    await markAllNotificationsRead();
    refresh();
  };

  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)}
        className={`relative rounded-lg border p-2 transition-colors ${open ? 'border-accent/50 bg-accent/15' : 'border-slate-700 hover:bg-white/5'}`}
        aria-label="Notifications">
        <svg className="h-4 w-4 text-slate-300" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.4-1.4A2 2 0 0118 14.2V11a6 6 0 10-12 0v3.2c0 .53-.21 1.04-.6 1.4L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unread > 0 ? (
          <span className="absolute -top-1.5 -right-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-bold text-white">
            {unread > 99 ? '99+' : unread}
          </span>
        ) : null}
      </button>

      {open ? (
        <div className="absolute right-0 top-full z-30 mt-2 w-80 rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
          <div className="flex items-center justify-between border-b border-slate-800 px-3 py-2">
            <p className="text-xs font-semibold text-slate-200">Notifications</p>
            {unread > 0 ? (
              <button className="text-[11px] text-accent hover:underline" onClick={readAll}>Mark all read</button>
            ) : null}
          </div>
          <div className="max-h-80 overflow-auto">
            {items.length === 0 ? <p className="p-4 text-sm text-slate-500">No notifications.</p> : (
              items.slice(0, 30).map((n) => (
                <div key={n.notification_id} className="border-b border-slate-800/60 px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-medium text-slate-200">{n.title || 'Notification'}</p>
                    {n.severity ? (
                      <span className="rounded-full border border-slate-700 px-1.5 py-0.5 text-[9px] uppercase text-slate-400">{n.severity}</span>
                    ) : null}
                  </div>
                  <p className="mt-0.5 text-[11px] text-slate-400 line-clamp-2">{n.body || ''}</p>
                  <p className="mt-1 text-[10px] text-slate-600">{n.simulated ? 'simulated' : n.channel || 'in-app'} · {n.created_at ? new Date(n.created_at).toLocaleTimeString() : ''}</p>
                </div>
              ))
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function Layout({ children, title }) {
  const role = getRole();
  const [demo, setDemo] = useState(false);
  const ws = useLiveSocket({ enabled: true });
  const wsState = WS_LABEL[ws.status] || WS_LABEL.disconnected;

  useEffect(() => {
    let mounted = true;
    fetch('/api/system/health', { headers: { Authorization: `Bearer ${localStorage.getItem('ai_sentinel_token')}` } })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (mounted && d) setDemo(Boolean(d.demo_mode)); })
      .catch(() => {});
    return () => { mounted = false; };
  }, []);

  return (
    <div className="min-h-screen bg-grid text-slate-100">
      <div className="flex">
        <aside className="hidden md:flex w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-950/60 h-screen sticky top-0 p-4">
          <div className="mb-6">
            <h1 className="text-xl font-bold tracking-tight text-accent">AI Sentinel</h1>
            <p className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mt-1">SOC Console</p>
            {demo ? (
              <span className="mt-2 inline-flex items-center gap-1 rounded-full border border-amber-400/50 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" /> Demo Mode
              </span>
            ) : null}
          </div>
          <nav className="space-y-1">
            {NAV.map((item) => (
              <NavLink key={item.to} item={item} location={window.location} />
            ))}
          </nav>
          <div className="mt-auto pt-4 border-t border-slate-800">
            <div className="mb-2 flex items-center gap-2 text-[11px] text-slate-500">
              <span className={`inline-block h-1.5 w-1.5 rounded-full ${wsState.cls}`} />
              <span>{wsState.text}</span>
            </div>
            <p className="text-xs text-slate-500 mb-2">Signed in as <span className="text-slate-300">{role || 'user'}</span></p>
            <button className="w-full rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-white/5" onClick={logout}>
              Log Out
            </button>
          </div>
        </aside>

        <main className="flex-1 min-w-0 p-4 md:p-6">
          <div className="mb-6 flex items-center justify-between gap-3 md:hidden">
            <h1 className="text-lg font-bold text-accent">AI Sentinel</h1>
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-2 py-1.5 text-[11px] text-slate-400">
                <span className={`inline-block h-1.5 w-1.5 rounded-full ${wsState.cls}`} />{wsState.text}
              </span>
              <NotificationBell />
              <button className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300" onClick={logout}>Log Out</button>
            </div>
          </div>
          <div className="mb-4 flex items-center justify-end gap-2 md:mb-6 md:hidden">
            {demo ? (
              <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/50 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" /> Demo Mode
              </span>
            ) : null}
          </div>
          {title ? <h2 className="text-2xl font-bold tracking-tight mb-4">{title}</h2> : null}
          <GlobalSearch />
          {children}
        </main>
      </div>
    </div>
  );
}