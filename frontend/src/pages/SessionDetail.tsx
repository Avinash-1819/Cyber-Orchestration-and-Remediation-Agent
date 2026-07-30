import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Download, CheckCircle, Loader2 } from 'lucide-react';

const API = 'http://localhost:8000/api/v1';

function SeverityBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium', LOW: 'sev-low', INFORMATIONAL: 'sev-info'
  };
  return <span className={`text-xs px-2 py-0.5 rounded font-mono font-semibold ${map[sev] || 'sev-info'}`}>{sev}</span>;
}

export default function SessionDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [session, setSession] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'findings' | 'summary' | 'raw'>('findings');

  useEffect(() => {
    if (!id) return;
    const tk = localStorage.getItem('core_token');
    if (!tk) { setLoading(false); return; }

    Promise.all([
      fetch(`${API}/sessions/${id}`, { headers: { Authorization: `Bearer ${tk}` } }).then(r => r.ok ? r.json() : null),
      fetch(`${API}/incidents/${id}/findings`, { headers: { Authorization: `Bearer ${tk}` } }).then(r => r.ok ? r.json() : { findings: [] }),
    ]).then(([s, f]) => {
      setSession(s);
      setFindings(f?.findings || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [id]);

  const download = (fmt: string) => {
    const tk = localStorage.getItem('core_token');
    if (!tk) return;
    fetch(`${API}/reports/${id}/${fmt}`, { headers: { Authorization: `Bearer ${tk}` } })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `core-report-${id?.slice(0, 8)}.${fmt}`;
        a.click();
      });
  };

  const stateData = session?.state || {};
  const execSummary = stateData.executive_summary || {};

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <button onClick={() => navigate('/sessions')}
            className="w-8 h-8 rounded-lg bg-zinc-800 hover:bg-zinc-700 flex items-center justify-center transition-colors">
            <ArrowLeft className="w-4 h-4 text-zinc-400" />
          </button>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-white">Session Detail</h1>
              <span className="font-mono text-xs text-purple-400 bg-purple-900/20 px-2 py-0.5 rounded">
                {id?.slice(0, 8)}...
              </span>
            </div>
            <p className="text-xs text-zinc-500 mt-0.5">
              {session?.created_at ? new Date(session.created_at).toLocaleString() : ''}
            </p>
          </div>
          <div className="flex gap-2">
            {['pdf', 'markdown', 'json'].map(fmt => (
              <button key={fmt} onClick={() => download(fmt)}
                className="flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 bg-purple-900/20 hover:bg-purple-900/40 border border-purple-700/30 px-3 py-1.5 rounded-lg transition-all">
                <Download className="w-3 h-3" />{fmt.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-20">
            <Loader2 className="w-8 h-8 text-purple-400 animate-spin" />
          </div>
        ) : !session ? (
          <div className="text-center py-20 text-zinc-500">Session not found</div>
        ) : (
          <>
            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              {[
                { label: 'Total Findings', value: findings.length, color: 'text-white' },
                { label: 'Critical', value: findings.filter(f => f.severity === 'CRITICAL').length, color: 'text-red-400' },
                { label: 'High', value: findings.filter(f => f.severity === 'HIGH').length, color: 'text-orange-400' },
                { label: 'Pipeline', value: session.pipeline || stateData.pipeline || '—', color: 'text-purple-400' },
              ].map(s => (
                <div key={s.label} className="glass rounded-xl p-4 border border-zinc-700/40">
                  <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
                  <div className="text-xs text-zinc-500 mt-0.5">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 mb-4 bg-zinc-800/40 p-1 rounded-xl border border-zinc-700/40 w-fit">
              {(['findings', 'summary', 'raw'] as const).map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    activeTab === tab
                      ? 'bg-purple-700 text-white shadow'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}>
                  {tab === 'findings' ? `Findings (${findings.length})` : tab === 'summary' ? 'Executive Summary' : 'Raw State'}
                </button>
              ))}
            </div>

            {/* Findings tab */}
            {activeTab === 'findings' && (
              <div className="flex flex-col gap-3">
                {findings.length === 0 ? (
                  <div className="text-center py-12">
                    <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                    <p className="text-zinc-400">No findings — analysis passed cleanly</p>
                  </div>
                ) : findings.map((f: any, i: number) => (
                  <div key={i} className="glass border border-zinc-700/40 rounded-xl p-4">
                    <div className="flex items-start gap-3">
                      <SeverityBadge sev={f.severity || 'INFO'} />
                      <div className="flex-1">
                        <p className="text-sm font-semibold text-gray-100">{f.title}</p>
                        <p className="text-xs text-zinc-400 mt-1 leading-relaxed">{f.description}</p>
                        {f.recommendation && (
                          <div className="mt-2 p-2 bg-emerald-900/20 border border-emerald-700/30 rounded-lg">
                            <p className="text-xs text-emerald-300"><strong>Fix:</strong> {f.recommendation}</p>
                          </div>
                        )}
                        {f.cve_ids?.length > 0 && (
                          <div className="flex gap-1 mt-2 flex-wrap">
                            {f.cve_ids.map((c: string) => (
                              <span key={c} className="text-xs font-mono bg-zinc-800 text-blue-400 px-2 py-0.5 rounded">{c}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Summary tab */}
            {activeTab === 'summary' && (
              <div className="glass border border-zinc-700/40 rounded-xl p-5">
                {Object.keys(execSummary).length === 0 ? (
                  <p className="text-zinc-500 text-sm">No executive summary available yet.</p>
                ) : (
                  <div className="space-y-4">
                    {execSummary.overview && (
                      <div>
                        <h3 className="text-sm font-semibold text-zinc-300 mb-1">Overview</h3>
                        <p className="text-sm text-zinc-400 leading-relaxed">{execSummary.overview}</p>
                      </div>
                    )}
                    {execSummary.risk_level && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-zinc-500">Risk Level:</span>
                        <SeverityBadge sev={execSummary.risk_level} />
                      </div>
                    )}
                    {execSummary.recommendations?.length > 0 && (
                      <div>
                        <h3 className="text-sm font-semibold text-zinc-300 mb-2">Top Recommendations</h3>
                        <ul className="space-y-1">
                          {execSummary.recommendations.map((r: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-zinc-400">
                              <span className="text-purple-400 shrink-0 mt-0.5">→</span>{r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Raw tab */}
            {activeTab === 'raw' && (
              <div className="glass border border-zinc-700/40 rounded-xl p-4">
                <pre className="text-xs text-gray-400 font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap">
                  {JSON.stringify(stateData, null, 2)}
                </pre>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
