import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { sessions } from '@/services/api';

interface SessionSummary {
  id: string;
  pipeline: string;
  input_type: string;
  status: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  created_at: string;
  completed_at: string | null;
}

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-green-500 shadow-[0_0_8px_#22c55e]',
  running: 'bg-amber-500 shadow-[0_0_8px_#f59e0b] animate-pulse',
  failed: 'bg-red-500 shadow-[0_0_8px_#ef4444]',
  awaiting_clarification: 'bg-sky-500 shadow-[0_0_8px_#0ea5e9]',
  pending: 'bg-slate-500',
};

export default function SessionHistory() {
  const navigate = useNavigate();
  const [rows, setRows] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    sessions.getAll()
      .then((list: SessionSummary[]) => {
        if (active) setRows(list);
      })
      .catch((e) => console.error('Failed to load sessions:', e))
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  return (
    <div id="session-history-page" className="animate-in fade-in">
      <h1 className="text-3xl font-bold text-white mb-8">Session History</h1>
      <div className="glass-panel overflow-hidden">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="text-xs uppercase bg-slate-800/80 text-slate-400 border-b border-slate-700">
            <tr>
              <th className="px-6 py-4">Session ID</th>
              <th className="px-6 py-4">Pipeline</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Findings</th>
              <th className="px-6 py-4">Date</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">Loading sessions...</td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">No sessions yet. Run a scan from the Scan page.</td>
              </tr>
            )}
            {rows.map((s) => (
              <tr
                key={s.id}
                onClick={() => navigate(`/sessions/${s.id}`)}
                className="border-b border-slate-700/50 hover:bg-slate-800/30 cursor-pointer transition-colors"
              >
                <td className="px-6 py-4 font-mono text-indigo-400">#{s.id.slice(0, 8)}</td>
                <td className="px-6 py-4">
                  <span className="px-2 py-1 rounded bg-slate-800 border border-slate-600 font-semibold text-xs">
                    Type {s.pipeline.replace('A_THEN_B', 'A+B')}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <span className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${STATUS_STYLES[s.status] || STATUS_STYLES.pending}`}></div>
                    {s.status.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-6 py-4">
                  {s.critical_count > 0 && <span className="text-red-400 font-bold">{s.critical_count} Critical</span>}
                  {s.high_count > 0 && <span className="text-amber-400 font-bold ml-2">{s.high_count} High</span>}
                  {s.critical_count === 0 && s.high_count === 0 && (
                    <span className="text-slate-500">{s.finding_count} findings</span>
                  )}
                </td>
                <td className="px-6 py-4 text-slate-500">{new Date(s.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
