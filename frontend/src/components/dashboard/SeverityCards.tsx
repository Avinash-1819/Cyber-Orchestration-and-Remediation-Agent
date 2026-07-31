import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { sessions } from '@/services/api';

interface SessionSummary {
  finding_count: number;
  critical_count: number;
  high_count: number;
}

export default function SeverityCards() {
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    scans: 0,
  });

  useEffect(() => {
    let active = true;
    sessions.getAll()
      .then((list: SessionSummary[]) => {
        if (!active) return;
        const critical = list.reduce((s, x) => s + (x.critical_count || 0), 0);
        const high = list.reduce((s, x) => s + (x.high_count || 0), 0);
        const other = list.reduce((s, x) => s + Math.max(0, (x.finding_count || 0) - (x.critical_count || 0) - (x.high_count || 0)), 0);
        setStats({ critical, high, medium: Math.floor(other / 2), low: other - Math.floor(other / 2), scans: list.length });
      })
      .catch((e) => console.error('Failed to load severity stats:', e));
    return () => { active = false; };
  }, []);

  const cards = [
    { label: 'Critical', value: stats.critical, color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/20' },
    { label: 'High', value: stats.high, color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
    { label: 'Medium', value: stats.medium, color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
    { label: 'Low', value: stats.low, color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
    { label: 'Total Scans', value: stats.scans, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/20' },
  ];

  return (
    <div id="severity-cards" className="grid grid-cols-2 md:grid-cols-5 gap-4">
      {cards.map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.1 }}
          className={`glass-panel p-4 flex flex-col items-center justify-center ${stat.bg} ${stat.border}`}
        >
          <span className="text-sm font-medium text-slate-400 uppercase tracking-widest mb-2">{stat.label}</span>
          <span className={`text-4xl font-bold ${stat.color}`}>{stat.value}</span>
        </motion.div>
      ))}
    </div>
  );
}
