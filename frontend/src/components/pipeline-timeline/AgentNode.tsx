import { motion } from 'framer-motion';
import clsx from 'clsx';
import { Check, Loader2, AlertCircle } from 'lucide-react';

interface Props {
  name: string;
  state: 'idle' | 'active' | 'complete' | 'error';
  index: number;
}

export default function AgentNode({ name, state, index }: Props) {
  const isGlow = state === 'active';
  
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay: index * 0.1 }}
      id={`agent-node-${name.toLowerCase().replace(' ', '-')}`}
      className="relative flex flex-col items-center"
    >
      <div 
        className={clsx(
          'w-16 h-16 rounded-2xl flex items-center justify-center border-2 z-10 transition-all duration-500 bg-slate-900',
          state === 'idle' && 'border-slate-700 text-slate-500',
          state === 'active' && 'border-indigo-500 text-indigo-400 shadow-[0_0_30px_rgba(99,102,241,0.6)]',
          state === 'complete' && 'border-green-500 text-green-400 bg-green-500/10 shadow-[0_0_15px_rgba(34,197,94,0.3)]',
          state === 'error' && 'border-red-500 text-red-400 bg-red-500/10 shadow-[0_0_20px_rgba(239,68,68,0.5)]'
        )}
      >
        {state === 'idle' && <span className="text-xl font-bold opacity-50">{index + 1}</span>}
        {state === 'active' && <Loader2 className="w-8 h-8 animate-spin" />}
        {state === 'complete' && <Check className="w-8 h-8" />}
        {state === 'error' && <AlertCircle className="w-8 h-8" />}
      </div>
      
      {isGlow && (
        <div className="absolute inset-0 rounded-2xl bg-indigo-500/20 animate-ping" style={{ animationDuration: '2s' }} />
      )}

      <span className={clsx(
        "mt-4 text-sm font-semibold tracking-wide text-center whitespace-nowrap",
        state === 'active' ? "text-indigo-300 drop-shadow-md" : "text-slate-400"
      )}>
        {name}
      </span>
    </motion.div>
  );
}
