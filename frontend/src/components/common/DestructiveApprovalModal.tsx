import { useState } from 'react';
import { AlertTriangle, Copy, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onApprove: () => void;
  command: string;
}

export default function DestructiveApprovalModal({ isOpen, onClose, onApprove, command }: Props) {
  const [input, setInput] = useState('');
  const isApproved = input === 'APPROVE';

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            id="destructive-modal"
            className="w-full max-w-lg glass-panel p-6 border-red-500/30 relative overflow-hidden"
          >
            <div className="absolute top-0 left-0 w-full h-1 bg-red-500"></div>
            
            <button onClick={onClose} className="absolute top-4 right-4 text-slate-400 hover:text-white">
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-start gap-4 mb-6">
              <div className="p-3 bg-red-500/10 rounded-full text-red-500">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-white mb-1">Destructive Remediation</h2>
                <p className="text-sm text-slate-400">This action will modify system state and cannot be undone.</p>
              </div>
            </div>

            <div className="bg-slate-900/80 p-4 rounded-lg border border-slate-700 font-mono text-sm mb-6 flex justify-between items-center group relative">
              <code className="text-orange-300 overflow-x-auto whitespace-pre">{command}</code>
              {isApproved ? (
                 <button id="copy-cmd-btn" onClick={() => navigator.clipboard.writeText(command)} className="p-2 bg-slate-800 rounded hover:bg-slate-700 text-slate-300">
                   <Copy className="w-4 h-4" />
                 </button>
              ) : (
                <div className="absolute inset-0 bg-slate-900/60 backdrop-blur-[1px] flex items-center justify-center text-xs font-semibold text-red-400 uppercase tracking-widest rounded-lg">
                  Requires Approval to Copy
                </div>
              )}
            </div>

            <div className="mb-6">
              <label className="block text-sm font-medium text-slate-400 mb-2">
                Type <span className="text-red-400 font-bold select-none">APPROVE</span> to confirm
              </label>
              <input
                id="approve-input"
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-red-500 transition-colors"
                placeholder="APPROVE"
              />
            </div>

            <div className="flex justify-end gap-3">
              <button id="cancel-btn" onClick={onClose} className="px-4 py-2 rounded-lg font-medium text-slate-300 hover:bg-slate-800 transition-colors">
                Cancel
              </button>
              <button
                id="confirm-btn"
                onClick={() => { if (isApproved) { onApprove(); onClose(); } }}
                disabled={!isApproved}
                className={`px-6 py-2 rounded-lg font-bold tracking-wide transition-all ${
                  isApproved 
                    ? 'bg-red-500 hover:bg-red-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.4)]' 
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                }`}
              >
                EXECUTE
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
