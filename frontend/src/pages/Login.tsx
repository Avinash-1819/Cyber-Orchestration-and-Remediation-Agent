import { Shield, Github } from 'lucide-react';
import { useState } from 'react';

export default function Login() {
  const [user, setUser] = useState('');
  const [pass, setPass] = useState('');

  return (
    <div id="login-page" className="min-h-screen bg-[#0F172A] flex items-center justify-center relative overflow-hidden bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(99,102,241,0.2),rgba(255,255,255,0))]">
      <div className="w-full max-w-md glass-panel p-8 relative z-10">
        <div className="flex flex-col items-center mb-10">
          <div className="w-16 h-16 rounded-xl bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center mb-4 shadow-[0_0_30px_rgba(99,102,241,0.3)]">
            <Shield className="text-indigo-400 w-8 h-8" />
          </div>
          <h1 className="text-3xl font-bold tracking-wider text-slate-100">SENTINEL<span className="text-indigo-500">AI</span></h1>
          <p className="text-slate-400 mt-2 text-sm uppercase tracking-widest">Authentication Required</p>
        </div>

        <form className="space-y-5" onSubmit={e => e.preventDefault()}>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Username</label>
            <input 
              id="login-user"
              type="text" 
              className="w-full bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
              value={user} onChange={e=>setUser(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Password</label>
            <input 
              id="login-pass"
              type="password" 
              className="w-full bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
              value={pass} onChange={e=>setPass(e.target.value)}
            />
          </div>
          <button id="login-submit" className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-3 rounded-lg transition-colors shadow-[0_0_15px_rgba(99,102,241,0.4)] mt-2">
            Access System
          </button>
        </form>

        <div className="mt-8 flex items-center justify-between">
          <hr className="w-full border-slate-700" />
          <span className="p-2 text-slate-500 text-xs font-semibold uppercase">OR</span>
          <hr className="w-full border-slate-700" />
        </div>

        <button id="github-login" className="mt-6 w-full bg-slate-800 hover:bg-slate-700 text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-3 border border-slate-600">
          <Github className="w-5 h-5" />
          Authenticate with GitHub
        </button>
      </div>
    </div>
  );
}
