import os
import json

base_dir = "/home/avinash/.gemini/antigravity/scratch/sentinel-ai/frontend"
os.makedirs(base_dir, exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/types"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/store"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/services"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/components/layout"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/components/common"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/components/dashboard"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/components/pipeline-timeline"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/components/reports"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "src/pages"), exist_ok=True)

files = {}

files["package.json"] = """{
  "name": "sentinel-ai-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@tanstack/react-query": "^5.0.0",
    "axios": "^1.6.0",
    "framer-motion": "^10.16.4",
    "lucide-react": "^0.292.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.18.0",
    "zustand": "^4.4.6",
    "clsx": "^2.0.0",
    "tailwind-merge": "^2.0.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.37",
    "@types/react-dom": "^18.2.15",
    "@vitejs/plugin-react": "^4.2.0",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.31",
    "tailwindcss": "^3.3.5",
    "typescript": "^5.2.2",
    "vite": "^5.0.0"
  }
}"""

files["vite.config.ts"] = """import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000
  }
})"""

files["tailwind.config.ts"] = """/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Outfit', 'sans-serif'],
      },
      colors: {
        slate: {
          900: '#0F172A',
          800: '#1E293B',
        },
        indigo: {
          500: '#6366F1',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#3B82F6',
          info: '#6B7280',
        }
      },
      backgroundColor: {
        glass: 'rgba(30, 41, 59, 0.7)',
      },
      backdropBlur: {
        xs: '2px',
      }
    },
  },
  plugins: [],
}"""

files["tsconfig.json"] = """{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}"""

files["tsconfig.node.json"] = """{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}"""

files["index.html"] = """<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <title>Sentinel AI</title>
  </head>
  <body class="bg-slate-900 text-slate-100 font-sans antialiased selection:bg-indigo-500/30">
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>"""

files["src/main.tsx"] = """import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './index.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const queryClient = new QueryClient()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)"""

files["src/App.tsx"] = """import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from '@/components/layout/Layout';
import Login from '@/pages/Login';
import Dashboard from '@/pages/Dashboard';
import Scan from '@/pages/Scan';
import SessionHistory from '@/pages/SessionHistory';
import SessionDetail from '@/pages/SessionDetail';
import Reports from '@/pages/Reports';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/auth/callback" element={<div>Auth Callback</div>} />
        
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/sessions" element={<SessionHistory />} />
          <Route path="/sessions/:id" element={<SessionDetail />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;"""

files["src/index.css"] = """@tailwind base;
@tailwind components;
@tailwind utilities;

@layer utilities {
  .glass-panel {
    @apply bg-glass backdrop-blur-md border border-slate-700/50 shadow-xl rounded-xl;
  }
}

/* Custom Scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: #334155;
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: #475569;
}

body {
  overflow-x: hidden;
}"""

files["src/types/index.ts"] = """export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface User {
  id: string;
  username: string;
}

export interface AuthState {
  token: string | null;
  user: User | null;
  setAuth: (token: string, user: User) => void;
  logout: () => void;
}

export interface Session {
  id: string;
  pipeline: 'A' | 'B' | 'C';
  status: 'running' | 'completed' | 'failed';
  finding_count: number;
  critical_count: number;
  high_count: number;
  created_at: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
}

export interface IOC {
  id: string;
  type: string;
  value: string;
}

export interface WsEvent {
  type: 'agent_started' | 'agent_completed' | 'agent_error' | 'classified' | 'needs_clarification' | 'trace' | 'state_snapshot' | 'ping';
  agent?: string;
  session_id?: string;
  data?: any;
}"""

files["src/store/auth.ts"] = """import { create } from 'zustand';
import { AuthState } from '../types';

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('token'),
  user: null,
  setAuth: (token, user) => {
    localStorage.setItem('token', token);
    set({ token, user });
  },
  logout: () => {
    localStorage.removeItem('token');
    set({ token: null, user: null });
  },
}));"""

files["src/services/api.ts"] = """import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api/v1',
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const auth = {
  localLogin: (data: any) => api.post('/auth/local/login', data),
  register: (data: any) => api.post('/auth/local/register', data),
};

export const scan = {
  start: (data: any) => api.post('/scan', data),
};

export const sessions = {
  getAll: () => api.get('/sessions').then(res => res.data),
  getById: (id: string) => api.get(`/sessions/${id}`).then(res => res.data),
};

export const reports = {
  download: (sessionId: string, format: string) => api.get(`/reports/${sessionId}/${format}`, { responseType: 'blob' }),
};

export const incidents = {
  getFindings: (sessionId: string) => api.get(`/incidents/${sessionId}/findings`).then(res => res.data),
  getIOCs: (sessionId: string) => api.get(`/incidents/${sessionId}/iocs`).then(res => res.data),
  approveRemediation: (data: any) => api.post('/incidents/remediation/approve', data),
};"""

files["src/services/websocket.ts"] = """type MessageHandler = (msg: any) => void;

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers: Set<MessageHandler> = new Set();

  constructor(sessionId: string, token: string) {
    this.url = `ws://localhost:8000/api/v1/ws/${sessionId}?token=${token}`;
  }

  connect() {
    this.ws = new WebSocket(this.url);
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handlers.forEach(h => h(data));
    };

    this.ws.onclose = () => {
      setTimeout(() => this.connect(), 3000);
    };
  }

  subscribe(handler: MessageHandler) {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
  }
}"""

files["src/components/layout/Sidebar.tsx"] = """import { Link, useLocation } from 'react-router-dom';
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
}"""

files["src/components/layout/TopBar.tsx"] = """import { Bell, UserCircle } from 'lucide-react';

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
}"""

files["src/components/layout/Layout.tsx"] = """import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';

export default function Layout() {
  return (
    <div className="flex min-h-screen bg-[#0a0f1c] bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(99,102,241,0.15),rgba(255,255,255,0))]">
      <Sidebar />
      <div className="flex-1 ml-64 flex flex-col relative">
        <TopBar />
        <main className="flex-1 p-8 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}"""

files["src/components/common/SeverityBadge.tsx"] = """import clsx from 'clsx';
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
}"""

files["src/components/common/LoadingPulse.tsx"] = """export default function LoadingPulse() {
  return (
    <div id="loading-pulse" className="flex items-center justify-center p-8">
      <div className="relative w-16 h-16 flex items-center justify-center">
        <div className="absolute inset-0 border-4 border-indigo-500/20 rounded-full"></div>
        <div className="absolute inset-0 border-4 border-indigo-500 rounded-full border-t-transparent animate-spin"></div>
        <div className="w-4 h-4 bg-indigo-500 rounded-full animate-pulse shadow-[0_0_15px_rgba(99,102,241,0.5)]"></div>
      </div>
    </div>
  );
}"""

files["src/components/common/DestructiveApprovalModal.tsx"] = """import { useState } from 'react';
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
}"""

files["src/components/common/ConfidenceBar.tsx"] = """interface Props {
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
}"""

files["src/components/dashboard/SeverityCards.tsx"] = """import { motion } from 'framer-motion';

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
}"""

files["src/components/dashboard/RecentFindings.tsx"] = """import SeverityBadge from '@/components/common/SeverityBadge';

const findings = [
  { id: '1', title: 'Exposed AWS Keys in repository', severity: 'critical', time: '10 mins ago' },
  { id: '2', title: 'SQL Injection vulnerability in Login', severity: 'high', time: '1 hr ago' },
  { id: '3', title: 'Outdated NPM packages', severity: 'medium', time: '3 hrs ago' },
];

export default function RecentFindings() {
  return (
    <div id="recent-findings" className="glass-panel p-6">
      <h3 className="text-lg font-semibold mb-4 text-white">Recent High-Priority Findings</h3>
      <div className="space-y-4">
        {findings.map((f) => (
          <div key={f.id} className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors cursor-pointer">
            <div className="flex items-center gap-4">
              <SeverityBadge level={f.severity as any} />
              <span className="text-slate-200 font-medium">{f.title}</span>
            </div>
            <span className="text-sm text-slate-500">{f.time}</span>
          </div>
        ))}
      </div>
    </div>
  );
}"""

files["src/components/pipeline-timeline/AgentNode.tsx"] = """import { motion } from 'framer-motion';
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
}"""

files["src/components/pipeline-timeline/PipelineTimeline.tsx"] = """import AgentNode from './AgentNode';

interface Props {
  pipelineType: 'A' | 'B' | 'C';
  activeAgent: string | null;
  completedAgents: string[];
  errorAgent: string | null;
}

const pipelines = {
  A: ['MasterOrchestrator', 'DevSecOpsAgent', 'ComplianceAgent', 'ExecReportingAgent'],
  B: ['MasterOrchestrator', 'IncidentTriageAgent', 'RemediationAgent', 'ThreatIntelAgent', 'ExecReportingAgent'],
  C: ['MasterOrchestrator', 'ThreatIntelAgent', 'ExecReportingAgent']
};

export default function PipelineTimeline({ pipelineType, activeAgent, completedAgents, errorAgent }: Props) {
  const agents = pipelines[pipelineType] || pipelines.A;

  return (
    <div id="pipeline-timeline" className="glass-panel p-10 relative overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-full bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none opacity-20"></div>
      
      <h3 className="text-xl font-semibold text-white mb-12 flex items-center gap-3 relative z-10">
        <div className="w-2 h-6 bg-indigo-500 rounded-sm"></div>
        Execution Pipeline: Type {pipelineType}
      </h3>

      <div className="flex items-start justify-between relative max-w-4xl mx-auto z-10">
        {/* Connection Line */}
        <div className="absolute top-8 left-8 right-8 h-0.5 bg-slate-800 -z-10">
          <div 
            className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-indigo-500 transition-all duration-1000 shadow-[0_0_10px_rgba(99,102,241,0.5)]" 
            style={{ 
              width: activeAgent ? `${(agents.indexOf(activeAgent) / (agents.length - 1)) * 100}%` : (completedAgents.length === agents.length ? '100%' : '0%') 
            }}
          />
        </div>

        {agents.map((agent, i) => {
          let state: 'idle' | 'active' | 'complete' | 'error' = 'idle';
          if (errorAgent === agent) state = 'error';
          else if (completedAgents.includes(agent)) state = 'complete';
          else if (activeAgent === agent) state = 'active';

          return <AgentNode key={agent} name={agent} state={state} index={i} />;
        })}
      </div>
    </div>
  );
}"""

files["src/components/reports/ReportDownloadPanel.tsx"] = """import { FileText, Download, FileJson } from 'lucide-react';

export default function ReportDownloadPanel({ sessionId }: { sessionId: string }) {
  const handleDownload = (format: string) => {
    // API call mock
    console.log(`Downloading ${format} for ${sessionId}`);
  };

  return (
    <div id="report-download-panel" className="glass-panel p-6 flex items-center justify-between">
      <div>
        <h3 className="text-lg font-semibold text-white">Execution Report</h3>
        <p className="text-sm text-slate-400">Download the comprehensive analysis report.</p>
      </div>
      <div className="flex gap-3">
        <button onClick={() => handleDownload('pdf')} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600">
          <FileText className="w-4 h-4 text-red-400" /> PDF
        </button>
        <button onClick={() => handleDownload('markdown')} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600">
          <Download className="w-4 h-4 text-blue-400" /> Markdown
        </button>
        <button onClick={() => handleDownload('json')} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors border border-slate-600">
          <FileJson className="w-4 h-4 text-green-400" /> JSON
        </button>
      </div>
    </div>
  );
}"""

files["src/components/reports/FindingsTable.tsx"] = """import { useState } from 'react';
import SeverityBadge from '../common/SeverityBadge';
import { Finding } from '@/types';

interface Props {
  findings: Finding[];
}

export default function FindingsTable({ findings }: Props) {
  const [filter, setFilter] = useState('ALL');

  const filtered = filter === 'ALL' ? findings : findings.filter(f => f.severity.toUpperCase() === filter);

  return (
    <div id="findings-table-container" className="glass-panel overflow-hidden">
      <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-900/50">
        <h3 className="font-semibold text-white">Identified Findings</h3>
        <select 
          id="severity-filter"
          value={filter} 
          onChange={(e) => setFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 text-white text-sm rounded-lg focus:ring-indigo-500 focus:border-indigo-500 p-2"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
        </select>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left text-slate-300" id="findings-table">
          <thead className="text-xs text-slate-400 uppercase bg-slate-800/50 border-b border-slate-700">
            <tr>
              <th className="px-6 py-4">ID</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">Title</th>
              <th className="px-6 py-4">Description</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id} className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-4 font-mono text-slate-500">{f.id}</td>
                <td className="px-6 py-4"><SeverityBadge level={f.severity} /></td>
                <td className="px-6 py-4 font-medium text-slate-200">{f.title}</td>
                <td className="px-6 py-4 text-slate-400">{f.description}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={4} className="px-6 py-8 text-center text-slate-500">No findings match the selected criteria.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}"""

files["src/pages/Login.tsx"] = """import { Shield, Github } from 'lucide-react';
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
}"""

files["src/pages/Dashboard.tsx"] = """import SeverityCards from '@/components/dashboard/SeverityCards';
import RecentFindings from '@/components/dashboard/RecentFindings';

export default function Dashboard() {
  return (
    <div id="dashboard-page" className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">SOC Dashboard</h1>
          <p className="text-slate-400">System status and recent threat intelligence.</p>
        </div>
      </div>

      <SeverityCards />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <RecentFindings />
        <div className="glass-panel p-6">
          <h3 className="text-lg font-semibold mb-4 text-white">Active Pipelines</h3>
          <div className="flex flex-col gap-3">
             <div className="p-4 bg-slate-800/50 rounded-lg border border-indigo-500/30 flex justify-between items-center relative overflow-hidden">
                <div className="absolute left-0 top-0 w-1 h-full bg-indigo-500 animate-pulse"></div>
                <div className="pl-2">
                  <div className="font-semibold text-indigo-100">Session #a1b2c3d4</div>
                  <div className="text-xs text-indigo-300">Pipeline B - RemediationAgent active</div>
                </div>
                <span className="px-2 py-1 bg-indigo-500/20 text-indigo-400 text-xs rounded border border-indigo-500/30">RUNNING</span>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}"""

files["src/pages/Scan.tsx"] = """import { useState } from 'react';
import { Send, Terminal } from 'lucide-react';
import PipelineTimeline from '@/components/pipeline-timeline/PipelineTimeline';

export default function Scan() {
  const [input, setInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  
  // Mock state for demo
  const [activeAgent, setActiveAgent] = useState<string | null>(null);
  const [completedAgents, setCompletedAgents] = useState<string[]>([]);
  const pipelineType: 'A'|'B'|'C' = 'A';

  const handleScan = () => {
    setIsScanning(true);
    setCompletedAgents([]);
    setActiveAgent('MasterOrchestrator');
    
    // Fake sequence
    setTimeout(() => {
      setCompletedAgents(['MasterOrchestrator']);
      setActiveAgent('DevSecOpsAgent');
    }, 2000);
    
    setTimeout(() => {
      setCompletedAgents(['MasterOrchestrator', 'DevSecOpsAgent']);
      setActiveAgent('ComplianceAgent');
    }, 4000);

    setTimeout(() => {
      setCompletedAgents(['MasterOrchestrator', 'DevSecOpsAgent', 'ComplianceAgent']);
      setActiveAgent('ExecReportingAgent');
    }, 6000);

    setTimeout(() => {
      setCompletedAgents(['MasterOrchestrator', 'DevSecOpsAgent', 'ComplianceAgent', 'ExecReportingAgent']);
      setActiveAgent(null);
      setIsScanning(false);
    }, 8000);
  };

  return (
    <div id="scan-page" className="max-w-5xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Initiate Analysis</h1>
        <p className="text-slate-400">Submit code, logs, or context for autonomous threat hunting.</p>
      </div>

      <div className="glass-panel p-6 border-indigo-500/30 relative group">
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-purple-500/5 rounded-xl pointer-events-none"></div>
        <div className="flex items-center gap-2 mb-4 text-indigo-400 font-mono text-sm">
          <Terminal className="w-4 h-4" />
          <span>target_input &gt;</span>
        </div>
        <textarea
          id="scan-input"
          className="w-full h-40 bg-slate-900/80 border border-slate-700 rounded-lg p-4 text-slate-300 font-mono text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all resize-none shadow-inner"
          placeholder="Paste source code, server logs, or describe the security incident..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <div className="mt-4 flex justify-end">
          <button
            id="scan-submit-btn"
            onClick={handleScan}
            disabled={!input || isScanning}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2.5 rounded-lg font-medium transition-all shadow-[0_0_15px_rgba(99,102,241,0.4)] disabled:opacity-50 disabled:shadow-none"
          >
            <Send className="w-4 h-4" />
            {isScanning ? 'Executing Pipeline...' : 'Launch Agents'}
          </button>
        </div>
      </div>

      {(isScanning || completedAgents.length > 0) && (
        <div className="space-y-8 animate-in fade-in duration-500">
          <PipelineTimeline 
            pipelineType={pipelineType}
            activeAgent={activeAgent}
            completedAgents={completedAgents}
            errorAgent={null}
          />
          
          <div className="glass-panel p-6 bg-black/40">
            <h4 className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-4">Live Event Feed</h4>
            <div className="font-mono text-sm space-y-2 h-40 overflow-y-auto">
              <div className="text-slate-500">[SYSTEM] Session initialized...</div>
              {completedAgents.includes('MasterOrchestrator') && <div className="text-blue-400">[MasterOrchestrator] Analyzed input, classified as source code. Selecting Pipeline A.</div>}
              {activeAgent === 'DevSecOpsAgent' && <div className="text-yellow-400 animate-pulse">[DevSecOpsAgent] Scanning for vulnerabilities...</div>}
              {completedAgents.includes('DevSecOpsAgent') && <div className="text-green-400">[DevSecOpsAgent] Complete. Found 2 issues.</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}"""

files["src/pages/SessionHistory.tsx"] = """import { Activity } from 'lucide-react';

export default function SessionHistory() {
  return (
    <div id="session-history-page" className="animate-in fade-in">
      <h1 className="text-3xl font-bold text-white mb-8">Session History</h1>
      <div className="glass-panel overflow-hidden">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="text-xs uppercase bg-slate-800/80 text-slate-400 border-b border-slate-700">
            <tr>
              <th className="px-6 py-4">Session ID</th>
              <th className="px-6 py-4">Pipeline</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Findings</th>
              <th className="px-6 py-4">Date</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-slate-700/50 hover:bg-slate-800/30 cursor-pointer transition-colors">
              <td className="px-6 py-4 font-mono text-indigo-400">#f4a1b2c3</td>
              <td className="px-6 py-4"><span className="px-2 py-1 rounded bg-slate-800 border border-slate-600 font-semibold text-xs">Type A</span></td>
              <td className="px-6 py-4 flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_#22c55e]"></div>Completed</td>
              <td className="px-6 py-4"><span className="text-red-400 font-bold">2 Critical</span></td>
              <td className="px-6 py-4 text-slate-500">2026-07-29</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}"""

files["src/pages/SessionDetail.tsx"] = """import { useParams } from 'react-router-dom';
import PipelineTimeline from '@/components/pipeline-timeline/PipelineTimeline';
import FindingsTable from '@/components/reports/FindingsTable';

export default function SessionDetail() {
  const { id } = useParams();

  return (
    <div id="session-detail-page" className="space-y-8 animate-in fade-in">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Session Analysis</h1>
        <p className="text-slate-400 font-mono text-sm">ID: {id}</p>
      </div>

      <PipelineTimeline 
        pipelineType="A"
        activeAgent={null}
        completedAgents={['MasterOrchestrator', 'DevSecOpsAgent', 'ComplianceAgent', 'ExecReportingAgent']}
        errorAgent={null}
      />

      <FindingsTable findings={[
        { id: 'F-001', severity: 'critical', title: 'Hardcoded Secret', description: 'AWS Access Key found in line 42.' }
      ]} />
    </div>
  );
}"""

files["src/pages/Reports.tsx"] = """import ReportDownloadPanel from '@/components/reports/ReportDownloadPanel';

export default function Reports() {
  return (
    <div id="reports-page" className="animate-in fade-in max-w-4xl space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Intelligence Reports</h1>
        <p className="text-slate-400">Generated artifacts and compliance documents.</p>
      </div>
      
      <div className="space-y-4">
        <ReportDownloadPanel sessionId="latest" />
      </div>
    </div>
  );
}"""

files["Dockerfile"] = """FROM node:20-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]"""

files["nginx.conf"] = """server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, no-transform";
    }
}"""

files[".env.example"] = """VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000/api/v1/ws"""

for filepath, content in files.items():
    full_path = os.path.join(base_dir, filepath)
    with open(full_path, "w") as f:
        f.write(content)
print(f"Created {len(files)} files successfully.")
