export default function SessionHistory() {
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
            <tr className="border-b border-slate-700/50 hover:bg-slate-800/30 cursor-pointer transition-colors">
              <td className="px-6 py-4 font-mono text-indigo-400">#f4a1b2c3</td>
              <td className="px-6 py-4"><span className="px-2 py-1 rounded bg-slate-800 border border-slate-600 font-semibold text-xs">Type A</span></td>
              <td className="px-6 py-4 flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_#22c55e]"></div>Completed</td>
              <td className="px-6 py-4"><span className="text-red-400 font-bold">2 Critical</span></td>
              <td className="px-6 py-4 text-slate-500">2026-07-29</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
