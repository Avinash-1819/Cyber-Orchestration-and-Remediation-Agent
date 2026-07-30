import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText, Clock, CheckCircle, Loader2, AlertTriangle, ChevronRight, Search } from 'lucide-react';

const API = 'http://localhost:8000/api/v1';

function statusIcon(status: string) {
  if (status === 'completed') return <CheckCircle className="w-4 h-4 text-emerald-400" />;
  if (status === 'running') return <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />;
  if (status === 'error') return <AlertTriangle className="w-4 h-4 text-red-400" />;
  return <Clock className="w-4 h-4 text-zinc-500" />;
}

export default function Sessions() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const tk = localStorage.getItem('core_token');
    if (!tk) { setLoading(false); return; }
    fetch(`${API}/sessions?limit=50`, { headers: { Authorization: `Bearer ${tk}` } })
      .then(r => r.ok ? r.json() : { sessions: [] })
      .then(d => { setSessions(d.sessions || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const filtered = sessions.filter(s =>
    !filter || JSON.stringify(s).toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-semibold text-white">Session History</h1>
            <p className="text-sm text-zinc-500 mt-0.5">All previous analysis sessions</p>
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Search sessions..."
              className="bg-zinc-800/60 border border-zinc-700/60 rounded-xl pl-9 pr-4 py-2 text-sm text-gray-300 placeholder-zinc-500 outline-none focus:border-purple-600/60 transition-colors w-56"
            />
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center items-center py-20">
            <Loader2 className="w-8 h-8 text-purple-400 animate-spin" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-20">
            <FileText className="w-12 h-12 text-zinc-700 mx-auto mb-3" />
            <p className="text-zinc-500">No sessions found</p>
            <p className="text-zinc-600 text-sm mt-1">Run your first analysis in the Agent tab</p>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {filtered.map((s: any) => (
              <button
                key={s.id}
                onClick={() => navigate(`/sessions/${s.id}`)}
                className="glass border border-zinc-700/40 hover:border-purple-600/40 rounded-xl p-4 text-left transition-all group"
              >
                <div className="flex items-start gap-3">
                  <div className="w-9 h-9 rounded-lg bg-zinc-800 flex items-center justify-center shrink-0 group-hover:bg-purple-900/30 transition-colors">
                    {statusIcon(s.status || 'completed')}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-purple-400">{(s.id || s.session_id)?.slice(0, 8)}...</span>
                      {s.pipeline && s.pipeline !== 'UNKNOWN' && (
                        <span className="text-xs bg-purple-900/30 text-purple-300 px-2 py-0.5 rounded-full border border-purple-700/30">
                          Pipeline {s.pipeline}
                        </span>
                      )}
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        s.status === 'completed' ? 'bg-emerald-900/30 text-emerald-400 border border-emerald-700/30' :
                        s.status === 'running' ? 'bg-purple-900/30 text-purple-400 border border-purple-700/30' :
                        'bg-zinc-800 text-zinc-400 border border-zinc-700'
                      }`}>
                        {s.status || 'completed'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-300 truncate">
                      {s.input_preview || s.input_type || 'Security analysis'}
                    </p>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-xs text-zinc-500">
                        {s.created_at ? new Date(s.created_at).toLocaleString() : 'Recent'}
                      </span>
                      {s.finding_count !== undefined && s.finding_count > 0 && (
                        <span className="text-xs text-amber-400">
                          {s.critical_count > 0 && `🔴${s.critical_count} `}
                          {s.high_count > 0 && `🟠${s.high_count} `}
                          {s.finding_count} total findings
                        </span>
                      )}
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-purple-400 transition-colors shrink-0 mt-2" />
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
