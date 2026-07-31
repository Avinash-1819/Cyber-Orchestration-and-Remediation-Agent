import { useState, useEffect } from 'react';
import ReportDownloadPanel from '@/components/reports/ReportDownloadPanel';
import { sessions } from '@/services/api';

interface SessionSummary {
  id: string;
  pipeline: string;
  input_type: string;
  status: string;
  created_at: string;
}

export default function Reports() {
  const [sessionList, setSessionList] = useState<SessionSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');

  useEffect(() => {
    let active = true;
    sessions.getAll()
      .then((list: SessionSummary[]) => {
        if (!active) return;
        setSessionList(list);
        if (list.length > 0) setSelectedId(list[0].id);
      })
      .catch((e) => console.error('Failed to load sessions:', e));
    return () => { active = false; };
  }, []);

  return (
    <div id="reports-page" className="animate-in fade-in max-w-4xl space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Intelligence Reports</h1>
        <p className="text-slate-400">Generated artifacts and compliance documents.</p>
      </div>

      <div className="glass-panel p-6 space-y-3">
        <label htmlFor="report-session-select" className="text-sm font-medium text-slate-300">
          Session
        </label>
        <select
          id="report-session-select"
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="w-full bg-slate-800 border border-slate-600 text-white text-sm rounded-lg focus:ring-indigo-500 focus:border-indigo-500 p-2.5"
        >
          {sessionList.length === 0 && <option value="">No sessions yet</option>}
          {sessionList.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id.slice(0, 8)} — {s.pipeline} ({s.status}) — {new Date(s.created_at).toLocaleString()}
            </option>
          ))}
        </select>
      </div>

      {selectedId ? (
        <ReportDownloadPanel sessionId={selectedId} />
      ) : (
        <div className="glass-panel p-6 text-center text-slate-400">
          No sessions available. Run a scan first.
        </div>
      )}
    </div>
  );
}
