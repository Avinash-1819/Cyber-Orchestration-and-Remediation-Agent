import { useState } from 'react';
import SeverityBadge from '../common/SeverityBadge';
import { Finding } from '@/types';

interface Props {
  findings: Finding[];
}

export default function FindingsTable({ findings }: Props) {
  const [filter, setFilter] = useState('ALL');

  const filtered = filter === 'ALL' ? findings : findings.filter(f => f.severity.toUpperCase() === filter);

  return (
    <div id="findings-table-container" className="glass-panel overflow-hidden">
      <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-900/50">
        <h3 className="font-semibold text-white">Identified Findings</h3>
        <select 
          id="severity-filter"
          value={filter} 
          onChange={(e) => setFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 text-white text-sm rounded-lg focus:ring-indigo-500 focus:border-indigo-500 p-2"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
        </select>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left text-slate-300" id="findings-table">
          <thead className="text-xs text-slate-400 uppercase bg-slate-800/50 border-b border-slate-700">
            <tr>
              <th className="px-6 py-4">ID</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">Title</th>
              <th className="px-6 py-4">Description</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id} className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-4 font-mono text-slate-500">{f.id}</td>
                <td className="px-6 py-4"><SeverityBadge level={f.severity} /></td>
                <td className="px-6 py-4 font-medium text-slate-200">{f.title}</td>
                <td className="px-6 py-4 text-slate-400">{f.description}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={4} className="px-6 py-8 text-center text-slate-500">No findings match the selected criteria.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
