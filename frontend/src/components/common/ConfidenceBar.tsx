interface Props {
  score: number;
}
export default function ConfidenceBar({ score }: Props) {
  return (
    <div id="confidence-bar" className="flex items-center gap-3">
      <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div 
          className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full shadow-[0_0_10px_rgba(99,102,241,0.5)] transition-all duration-1000"
          style={{ width: `${score * 100}%` }}
        />
      </div>
      <span className="text-xs font-mono text-slate-400 w-8">{(score * 100).toFixed(0)}%</span>
    </div>
  );
}
