import { useEffect, useRef, useState } from 'react';
import { askChatbot } from '../api';
import Layout from './Layout';

const SUGGESTIONS = [
  'What is the current risk level?',
  'Summarize open incidents.',
  'List current alerts.',
  'How is server health?',
  'What should I do next?',
  'Which MITRE techniques are active?',
];

export default function AssistantPage() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const send = async (text) => {
    const q = (text || input).trim();
    if (!q || busy) return;
    setInput('');
    setMessages((m) => [...m, { role: 'user', content: q }]);
    setBusy(true);
    try {
      const r = await askChatbot(q);
      setMessages((m) => [...m, { role: 'assistant', content: r.answer }]);
    } catch (e) {
      setMessages((m) => [...m, { role: 'assistant', content: `Error: ${e.message}` }]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Layout title="AI Security Assistant">
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4" style={{ height: 'calc(100vh - 140px)' }}>
        <div className="panel hidden xl:flex flex-col">
          <h3 className="title mb-3">Suggestions</h3>
          <div className="space-y-2">
            {SUGGESTIONS.map((s) => (
              <button key={s} className="w-full rounded-lg border border-slate-700 px-3 py-2 text-left text-xs text-slate-300 hover:border-accent/40 hover:bg-white/5"
                onClick={() => send(s)}>
                {s}
              </button>
            ))}
          </div>
          <p className="mt-auto text-[11px] text-slate-500 leading-relaxed">
            Answers are grounded strictly in live telemetry stored in SQLite. No external LLM is invoked and no data is fabricated.
          </p>
        </div>

        <div className="panel xl:col-span-3 flex flex-col min-h-0">
          <div className="flex-1 overflow-auto space-y-3 pr-1">
            {messages.length === 0 ? (
              <div className="text-center text-sm text-slate-500 py-12">
                Ask about risk level, incidents, alerts, server health, event volume, MITRE techniques, or recommended responses.
              </div>
            ) : messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-xl px-4 py-2.5 text-sm whitespace-pre-wrap ${
                  m.role === 'user' ? 'bg-accent/15 border border-accent/30 text-slate-100' : 'bg-slate-900 border border-slate-700 text-slate-200'}`}>
                  {m.content}
                </div>
              </div>
            ))}
            {busy ? <div className="text-xs text-slate-500">Analyzing live telemetry…</div> : null}
            <div ref={bottomRef} />
          </div>

          <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); send(); }}>
            <input className="input" placeholder="Ask about the environment…" value={input} onChange={(e) => setInput(e.target.value)} />
            <button className="btn shrink-0" type="submit" disabled={busy}>Ask</button>
          </form>
        </div>
      </div>
    </Layout>
  );
}
