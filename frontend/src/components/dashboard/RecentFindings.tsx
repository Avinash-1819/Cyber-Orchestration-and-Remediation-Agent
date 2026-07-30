import SeverityBadge from '@/components/common/SeverityBadge';

const findings = [
  { id: '1', title: 'Exposed AWS Keys in repository', severity: 'critical', time: '10 mins ago' },
  { id: '2', title: 'SQL Injection vulnerability in Login', severity: 'high', time: '1 hr ago' },
  { id: '3', title: 'Outdated NPM packages', severity: 'medium', time: '3 hrs ago' },
];

export default function RecentFindings() {
  return (
    <div id="recent-findings" className="glass-panel p-6">
      <h3 className="text-lg font-semibold mb-4 text-white">Recent High-Priority Findings</h3>
      <div className="space-y-4">
        {findings.map((f) => (
          <div key={f.id} className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors cursor-pointer">
            <div className="flex items-center gap-4">
              <SeverityBadge level={f.severity as any} />
              <span className="text-slate-200 font-medium">{f.title}</span>
            </div>
            <span className="text-sm text-slate-500">{f.time}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
