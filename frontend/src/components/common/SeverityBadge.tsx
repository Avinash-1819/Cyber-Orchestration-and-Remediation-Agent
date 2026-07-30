import clsx from 'clsx';
import { Severity } from '@/types';

const colors = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.2)]',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20 shadow-[0_0_10px_rgba(249,115,22,0.2)]',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
};

export default function SeverityBadge({ level }: { level: Severity }) {
  return (
    <span id={`badge-${level}`} className={clsx('px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border', colors[level])}>
      {level}
    </span>
  );
}
