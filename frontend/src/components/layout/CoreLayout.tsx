import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { Shield, MessageSquare, History, LogOut, Zap } from 'lucide-react';

export default function CoreLayout() {
  const navigate = useNavigate();

  const logout = () => {
    localStorage.removeItem('core_token');
    navigate('/');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a0f]">
      {/* Sidebar */}
      <aside className="w-[220px] shrink-0 flex flex-col border-r border-zinc-800/60 bg-[#0d0d14]">
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-5 border-b border-zinc-800/60">
          <div className="w-8 h-8 rounded-lg bg-purple-700 flex items-center justify-center shadow-lg shadow-purple-900/40">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-tight">CORE</div>
            <div className="text-[10px] text-zinc-500 leading-tight">Cyber Orchestration</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-3 space-y-1">
          <NavLink to="/agent" className={({ isActive }) =>
            `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all group ${
              isActive
                ? 'bg-purple-700/30 text-purple-300 border border-purple-700/40'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`
          }>
            {({ isActive }) => (
              <>
                <MessageSquare className={`w-4 h-4 ${isActive ? 'text-purple-400' : 'text-zinc-500 group-hover:text-zinc-300'}`} />
                <span className="font-medium">Agent</span>
                {isActive && <Zap className="w-3 h-3 text-purple-400 ml-auto animate-pulse" />}
              </>
            )}
          </NavLink>

          <NavLink to="/sessions" className={({ isActive }) =>
            `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all group ${
              isActive
                ? 'bg-purple-700/30 text-purple-300 border border-purple-700/40'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`
          }>
            <History className="w-4 h-4 text-zinc-500 group-hover:text-zinc-300" />
            <span className="font-medium">Sessions</span>
          </NavLink>
        </nav>

        {/* Agent status */}
        <div className="px-3 pb-3">
          <div className="glass rounded-xl p-3 border border-zinc-700/40">
            <div className="text-[10px] text-zinc-500 mb-2 font-mono tracking-widest">AGENTS READY</div>
            {[
              { name: 'Orchestrator', icon: '🎯' },
              { name: 'DevSecOps', icon: '🛡️' },
              { name: 'Triage', icon: '🔍' },
              { name: 'Remediation', icon: '⚡' },
              { name: 'ThreatIntel', icon: '🧠' },
              { name: 'Reporting', icon: '📊' },
            ].map(a => (
              <div key={a.name} className="flex items-center gap-2 py-0.5">
                <span className="text-xs">{a.icon}</span>
                <span className="text-xs text-zinc-400">{a.name}</span>
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse-slow" />
              </div>
            ))}
          </div>
        </div>

        {/* Bottom */}
        <div className="px-2 pb-3 border-t border-zinc-800/60 pt-2">
          <button
            onClick={logout}
            className="flex items-center gap-3 w-full px-3 py-2 rounded-xl text-sm text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60 transition-all"
          >
            <LogOut className="w-4 h-4" />
            <span>Clear Session</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}
