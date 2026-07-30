import { motion } from 'framer-motion';

const stats = [
  { label: 'Critical', value: 12, color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/20' },
  { label: 'High', value: 34, color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
  { label: 'Medium', value: 89, color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
  { label: 'Low', value: 156, color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
  { label: 'Total Scans', value: 1250, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/20' },
];

export default function SeverityCards() {
  return (
    <div id="severity-cards" className="grid grid-cols-2 md:grid-cols-5 gap-4">
      {stats.map((stat, i) => (
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
