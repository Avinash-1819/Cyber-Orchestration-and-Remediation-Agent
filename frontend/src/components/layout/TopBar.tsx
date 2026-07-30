import { Bell, UserCircle } from 'lucide-react';

export default function TopBar() {
  return (
    <header id="top-bar" className="h-16 glass-panel border-x-0 border-t-0 rounded-none flex items-center justify-between px-8 sticky top-0 z-10 backdrop-blur-xl">
      <div className="text-sm font-medium text-slate-400 uppercase tracking-widest">
        Security Operations Center
      </div>
      <div className="flex items-center gap-4">
        <button id="notifications-btn" className="p-2 text-slate-400 hover:text-slate-200 transition-colors relative">
          <Bell className="w-5 h-5" />
          <span className="absolute top-2 right-2 w-2 h-2 bg-severity-critical rounded-full animate-pulse"></span>
        </button>
        <div className="h-6 w-px bg-slate-700"></div>
        <button id="profile-btn" className="flex items-center gap-2 text-slate-300 hover:text-white transition-colors">
          <UserCircle className="w-6 h-6" />
          <span className="font-medium text-sm">Analyst</span>
        </button>
      </div>
    </header>
  );
}
