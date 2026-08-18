import { getRole, logout } from '../api';

const NAV = [
  { to: '/', label: 'Overview', icon: 'M3 12l9-9 9 9M5 10v10h5v-6h4v6h5V10', end: true },
  { to: '/events', label: 'Live Events', icon: 'M13 5l7 7-7 7M5 5l7 7-7 7' },
  { to: '/alerts', label: 'Alerts', icon: 'M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/incidents', label: 'Incidents', icon: 'M9 12h6m-6 4h6M9 8h6M5 3h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z' },
  { to: '/network', label: 'Network', icon: 'M8 9l-5 5 5 5M16 9l5 5-5 5M13 4l-2 16' },
  { to: '/rules', label: 'Detection Rules', icon: 'M12 3v3m6.4-1.4l-2.1 2.1M21 12h-3m1.4 6.4l-2.1-2.1M12 21v-3m-6.4 1.4l2.1-2.1M3 12h3m-1.4-6.4l2.1 2.1M9 16a4 4 0 116 0' },
  { to: '/phishing', label: 'Phishing Analysis', icon: 'M13 6a2 2 0 11-4 0 2 2 0 014 0zM8 10h8l-1 10H9L8 10z' },
  { to: '/assistant', label: 'AI Assistant', icon: 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
  { to: '/system', label: 'System', icon: 'M10.3 4.2l1-1a1 1 0 011.4 0l1 1A3 3 0 0115 4h1a1 1 0 011 1v1a3 3 0 001.8 2.7l1 .6a1 1 0 010 1.4l-1 1a3 3 0 00-1 2.2v1a1 1 0 01-1 1h-1a3 3 0 01-2.7-1.8l-.6-1a1 1 0 00-1.4 0l-1 1A3 3 0 017 16h-1a1 1 0 01-1-1v-1a3 3 0 00-1.8-2.7l-1-.6a1 1 0 010-1.4l1-1A3 3 0 004 6V5a1 1 0 011-1h1a3 3 0 002.3-1.8z' },
];

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

export default function Layout({ children, title }) {
  const role = getRole();
  return (
    <div className="min-h-screen bg-grid text-slate-100">
      <div className="flex">
        <aside className="hidden md:flex w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-950/60 h-screen sticky top-0 p-4">
          <div className="mb-6">
            <h1 className="text-xl font-bold tracking-tight text-accent">AI Sentinel</h1>
            <p className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mt-1">SOC Console</p>
          </div>
          <nav className="space-y-1">
            {NAV.map((item) => (
              <NavLink key={item.to} item={item} location={window.location} />
            ))}
          </nav>
          <div className="mt-auto pt-4 border-t border-slate-800">
            <p className="text-xs text-slate-500 mb-2">Signed in as <span className="text-slate-300">{role || 'user'}</span></p>
            <button className="w-full rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-white/5" onClick={logout}>
              Log Out
            </button>
          </div>
        </aside>

        <main className="flex-1 min-w-0 p-4 md:p-6">
          <div className="mb-6 flex items-center justify-between gap-3 md:hidden">
            <h1 className="text-lg font-bold text-accent">AI Sentinel</h1>
            <button className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300" onClick={logout}>Log Out</button>
          </div>
          {title ? <h2 className="text-2xl font-bold tracking-tight mb-4">{title}</h2> : null}
          {children}
        </main>
      </div>
    </div>
  );
}
