import { Link, useLocation } from 'react-router-dom';
import { Shield, Activity, List, FileText, Settings } from 'lucide-react';
import clsx from 'clsx';

const navItems = [
  { path: '/', icon: Shield, label: 'Dashboard' },
  { path: '/scan', icon: Activity, label: 'New Scan' },
  { path: '/sessions', icon: List, label: 'Sessions' },
  { path: '/reports', icon: FileText, label: 'Reports' },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <aside id="main-sidebar" className="w-64 glass-panel border-y-0 border-l-0 rounded-none h-screen fixed left-0 top-0 flex flex-col p-4 z-10">
      <div className="flex items-center gap-3 mb-10 px-2 mt-4">
        <div className="w-8 h-8 rounded bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center">
          <Shield className="text-indigo-400 w-5 h-5" />
        </div>
        <h1 className="text-xl font-bold tracking-wider text-slate-100">SENTINEL<span className="text-indigo-500">AI</span></h1>
      </div>

      <nav className="flex-1 space-y-2">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            id={`nav-link-${item.label.toLowerCase().replace(' ', '-')}`}
            className={clsx(
              'flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200',
              location.pathname === item.path
                ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.15)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            )}
          >
            <item.icon className="w-5 h-5" />
            <span className="font-medium">{item.label}</span>
          </Link>
        ))}
      </nav>

      <div className="mt-auto">
        <button id="nav-settings" className="flex items-center gap-3 px-4 py-3 w-full text-left rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 transition-all">
          <Settings className="w-5 h-5" />
          <span className="font-medium">Settings</span>
        </button>
      </div>
    </aside>
  );
}
