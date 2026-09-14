import { useEffect, useState } from 'react';
import { mitreCoverage } from '../api';
import Layout from './Layout';
import { Empty, Loading } from './ui';

const TECH_STYLES = {
  VERIFIED_LIVE: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40',
  DETECTING: 'bg-sky-500/15 text-sky-300 border-sky-400/40',
  RULES_DISABLED: 'bg-amber-500/15 text-amber-300 border-amber-400/40',
  OBSERVED_NO_RULES: 'bg-red-500/15 text-red-300 border-red-400/40',
};

const PRIORITY_STYLES = { high: 'text-red-400', medium: 'text-amber-300', low: 'text-sky-300' };

export default function MitrePage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    mitreCoverage().then(setData).catch(() => setData(null)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Layout title="MITRE ATT&CK"><Loading /></Layout>;

  const cov = data?.coverage || {};
  const techniques = data?.techniques || [];
  const gaps = data?.gap_recommendations || [];

  return (
    <Layout title="MITRE ATT&CK Coverage">
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
        <Stat label="Techniques Covered" value={cov.techniques_covered ?? 0} tone="text-emerald-300" />
        <Stat label="Verified Live" value={cov.verified_live ?? 0} tone="text-sky-300" />
        <Stat label="Detecting Only" value={cov.detecting_only ?? 0} tone="text-accent" />
        <Stat label="Rules Disabled" value={cov.rules_disabled ?? 0} tone="text-amber-300" />
        <Stat label="Observed, No Rules" value={cov.observed_no_rules ?? 0} tone="text-red-400" />
      </div>

      {cov.tactics_covered?.length ? (
        <div className="mb-4 flex flex-wrap gap-2">
          {(cov.tactics_covered || []).map((t) => (
            <span key={t} className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] uppercase tracking-wide text-accent">{t}</span>
          ))}
        </div>
      ) : null}

      <div className="panel mb-4">
        <h3 className="title mb-3">Detection Gaps</h3>
        {gaps.length === 0 ? <Empty message="No detection gaps identified from the live rule + incident corpus." /> : (
          <div className="space-y-2">
            {gaps.map((g, i) => (
              <div key={i} className="rounded-lg border border-slate-800 p-2.5 text-sm">
                <div className="flex items-center justify-between">
                  <span className={`font-medium ${PRIORITY_STYLES[g.priority] || PRIORITY_STYLES.medium}`}>{g.priority.toUpperCase()}</span>
                  <span className="font-mono text-xs text-accent">{g.type}</span>
                </div>
                <p className="mt-1 text-slate-300">{g.recommendation}</p>
                {g.technique ? <p className="mt-1 text-[11px] text-slate-500">{g.technique} · {g.tactic}</p> : null}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="panel">
        <h3 className="title mb-3">Technique Inventory ({techniques.length})</h3>
        {techniques.length === 0 ? <Empty message="No MITRE techniques recorded in rules, alerts or incidents yet." /> : (
          <div className="max-h-[30rem] overflow-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 uppercase tracking-wide">
                  <th className="pb-2">Technique</th>
                  <th className="pb-2">Tactic</th>
                  <th className="pb-2">Enabled</th>
                  <th className="pb-2">Disabled</th>
                  <th className="pb-2">Inc</th>
                  <th className="pb-2">Alerts</th>
                  <th className="pb-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {techniques.map((t) => (
                  <tr key={t.technique} className="border-t border-slate-800">
                    <td className="py-1.5 font-mono text-accent">{t.technique}</td>
                    <td className="py-1.5 text-slate-400">{t.tactic}</td>
                    <td className="py-1.5 font-mono">{t.enabled_rules.length}</td>
                    <td className="py-1.5 font-mono">{t.disabled_rules.length}</td>
                    <td className="py-1.5 font-mono">{t.incidents}</td>
                    <td className="py-1.5 font-mono">{t.alerts}</td>
                    <td className="py-1.5">
                      <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] uppercase ${TECH_STYLES[t.status] || TECH_STYLES.OBSERVED_NO_RULES}`}>
                        {t.status}
                      </span>
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

function Stat({ label, value, tone }) {
  return (
    <div className="panel">
      <p className="label">{label}</p>
      <p className={`value ${tone}`}>{value}</p>
    </div>
  );
}