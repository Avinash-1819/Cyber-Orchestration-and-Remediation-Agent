import { useState, useEffect } from 'react';
import SeverityBadge from '@/components/common/SeverityBadge';
import { sessions, incidents } from '@/services/api';

interface FindingRow {
  id: string;
  title: string;
  severity: string;
  time: string;
}

function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min${mins === 1 ? '' : 's'} ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hr${hrs === 1 ? '' : 's'} ago`;
  return `${Math.floor(hrs / 24)} days ago`;
}

export default function RecentFindings() {
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const list: any[] = await sessions.getAll();
        if (!active || list.length === 0) return;
        const latest = list[0];
        const res: any = await incidents.getFindings(latest.id);
        if (!active) return;
        const rows = (res.findings || [])
          .filter((f: any) => ['CRITICAL', 'HIGH'].includes(String(f.severity || '').toUpperCase()))
          .slice(0, 6)
          .map((f: any) => ({
            id: String(f.id),
            title: f.title || 'Finding',
            severity: String(f.severity || 'medium').toLowerCase(),
            time: timeAgo(latest.created_at),
          }));
        setFindings(rows);
      } catch (e) {
        console.error('Failed to load recent findings:', e);
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  return (
    <div id="recent-findings" className="glass-panel p-6">
      <h3 className="text-lg font-semibold mb-4 text-white">Recent High-Priority Findings</h3>
      {loading ? (
        <p className="text-sm text-slate-500">Loading findings...</p>
      ) : findings.length === 0 ? (
        <p className="text-sm text-slate-500">No findings yet. Run a scan to populate the dashboard.</p>
      ) : (
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
      )}
    </div>
  );
}
