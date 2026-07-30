import SeverityCards from '@/components/dashboard/SeverityCards';
import RecentFindings from '@/components/dashboard/RecentFindings';

export default function Dashboard() {
  return (
    <div id="dashboard-page" className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">SOC Dashboard</h1>
          <p className="text-slate-400">System status and recent threat intelligence.</p>
        </div>
      </div>

      <SeverityCards />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <RecentFindings />
        <div className="glass-panel p-6">
          <h3 className="text-lg font-semibold mb-4 text-white">Active Pipelines</h3>
          <div className="flex flex-col gap-3">
             <div className="p-4 bg-slate-800/50 rounded-lg border border-indigo-500/30 flex justify-between items-center relative overflow-hidden">
                <div className="absolute left-0 top-0 w-1 h-full bg-indigo-500 animate-pulse"></div>
                <div className="pl-2">
                  <div className="font-semibold text-indigo-100">Session #a1b2c3d4</div>
                  <div className="text-xs text-indigo-300">Pipeline B - RemediationAgent active</div>
                </div>
                <span className="px-2 py-1 bg-indigo-500/20 text-indigo-400 text-xs rounded border border-indigo-500/30">RUNNING</span>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
