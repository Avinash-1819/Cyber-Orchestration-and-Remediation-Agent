import { Outlet, NavLink, useNavigate, useSearchParams } from 'react-router-dom';
import { Shield, MessageSquare, History, LogOut, Zap, ChevronDown, Check, LayoutGrid, Sliders } from 'lucide-react';
import { useState } from 'react';

const SCANNER_OPTIONS = [
  { id: 'auto', icon: '⚡', label: 'Auto Orchestration', desc: 'All Agents — Auto Classifier' },
  { id: 'sast', icon: '🛡️', label: 'SAST Code Scanner', desc: 'DevSecOpsAgent' },
  { id: 'docker', icon: '🐳', label: 'Dockerfile Auditor', desc: 'DevSecOpsAgent' },
  { id: 'iac', icon: '🏗️', label: 'Terraform / IaC Analyzer', desc: 'DevSecOps + Compliance' },
  { id: 'triage', icon: '📊', label: 'Incident Triage Engine', desc: 'Triage + Remediation' },
  { id: 'enricher', icon: '🔍', label: 'Threat Enricher', desc: 'Triage + ThreatIntel' },
  { id: 'compliance', icon: '📜', label: 'GRC Compliance Mapper', desc: 'Compliance + ExecReport' },
  { id: 'cve', icon: '🎯', label: 'CVE & ATT&CK Intel', desc: 'ThreatIntelAgent' },
  { id: 'report', icon: '📄', label: 'Executive PDF Report', desc: 'All Core Agents' },
];

const ALL_SUB_AGENTS = [
  { id: 'IncidentTriageAgent', name: 'Incident Triage', icon: '🔍' },
  { id: 'RemediationAgent', name: 'Remediation', icon: '⚡' },
  { id: 'DevSecOpsAgent', name: 'DevSecOps', icon: '🛡️' },
  { id: 'ComplianceAgent', name: 'Compliance', icon: '📋' },
  { id: 'ThreatIntelAgent', name: 'Threat Intel', icon: '🧠' },
  { id: 'ExecReportingAgent', name: 'Exec Reporting', icon: '📊' },
];

export default function CoreLayout() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [enabledAgents, setEnabledAgents] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem('core_enabled_agents');
      if (saved) return JSON.parse(saved);
    } catch {}
    return {
      IncidentTriageAgent: true,
      RemediationAgent: true,
      DevSecOpsAgent: true,
      ComplianceAgent: true,
      ThreatIntelAgent: true,
      ExecReportingAgent: true,
    };
  });

  const toggleAgent = (agentId: string) => {
    setEnabledAgents(prev => {
      const next = { ...prev, [agentId]: !prev[agentId] };
      localStorage.setItem('core_enabled_agents', JSON.stringify(next));
      return next;
    });
  };

  const currentScannerId = searchParams.get('scanner') || 'auto';
  const selectedOption = SCANNER_OPTIONS.find(s => s.id === currentScannerId) || SCANNER_OPTIONS[0];

  const handleSelectScanner = (id: string) => {
    setDropdownOpen(false);
    if (id === 'auto') {
      navigate('/agent');
    } else {
      navigate(`/agent?scanner=${id}`);
    }
  };

  const logout = () => {
    localStorage.removeItem('core_token');
    navigate('/');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a0f]">
      {/* Sidebar */}
      <aside className="w-[245px] shrink-0 flex flex-col border-r border-zinc-800/60 bg-[#0d0d14]">
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-zinc-800/60 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-purple-700 flex items-center justify-center shadow-lg shadow-purple-900/40 shrink-0">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-tight">CORE</div>
            <div className="text-[10px] text-zinc-500 leading-tight">Cyber Orchestration</div>
          </div>
        </div>

        {/* Sidebar scrollable content */}
        <div className="flex-1 overflow-y-auto px-3 py-3 space-y-4">
          {/* Nav Links */}
          <div className="space-y-1">
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
                  <span className="font-medium">Agent Chat</span>
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
          </div>

          {/* Scanner Selection Section */}
          <div className="pt-2 border-t border-zinc-800/60">
            <div className="text-[10px] text-zinc-500 mb-2 font-mono tracking-wider flex items-center gap-1.5 px-1">
              <LayoutGrid className="w-3 h-3 text-purple-400" />
              SELECT SCANNER
            </div>

            {/* Dropdown */}
            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="w-full flex items-center justify-between gap-2 px-3 py-2.5 bg-zinc-800/60 hover:bg-zinc-800 border border-zinc-700/60 rounded-xl text-left transition-all group"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-base shrink-0">{selectedOption.icon}</span>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-gray-200 truncate">{selectedOption.label}</div>
                    <div className="text-[10px] text-zinc-500 truncate">{selectedOption.desc}</div>
                  </div>
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-zinc-400 shrink-0 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {dropdownOpen && (
                <div className="absolute left-0 right-0 mt-1.5 z-50 bg-[#161622] border border-zinc-700/80 rounded-xl shadow-2xl overflow-hidden py-1 max-h-[320px] overflow-y-auto">
                  {SCANNER_OPTIONS.map(opt => (
                    <button
                      key={opt.id}
                      onClick={() => handleSelectScanner(opt.id)}
                      className={`w-full flex items-start gap-2.5 px-3 py-2 text-left hover:bg-purple-900/30 transition-colors ${
                        opt.id === currentScannerId ? 'bg-purple-900/40 text-purple-300 font-medium' : 'text-zinc-300'
                      }`}
                    >
                      <span className="text-base shrink-0 mt-0.5">{opt.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs leading-snug">{opt.label}</div>
                        <div className="text-[10px] text-zinc-500 truncate">{opt.desc}</div>
                      </div>
                      {opt.id === currentScannerId && <Check className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Enable / Disable Agents Toggle Panel */}
          <div className="pt-2 border-t border-zinc-800/60">
            <div className="text-[10px] text-zinc-500 mb-2 font-mono tracking-wider flex items-center justify-between px-1">
              <span className="flex items-center gap-1.5">
                <Sliders className="w-3 h-3 text-purple-400" />
                ENABLE AGENTS
              </span>
              <span className="text-[9px] text-purple-400">
                {Object.values(enabledAgents).filter(Boolean).length}/6 Active
              </span>
            </div>

            <div className="glass rounded-xl p-2.5 border border-zinc-700/40 space-y-1.5">
              {ALL_SUB_AGENTS.map(agent => {
                const isEnabled = enabledAgents[agent.id] !== false;
                return (
                  <button
                    key={agent.id}
                    onClick={() => toggleAgent(agent.id)}
                    className={`w-full flex items-center justify-between px-2 py-1 rounded-lg text-xs transition-all ${
                      isEnabled ? 'text-gray-200 hover:bg-zinc-800/60' : 'text-zinc-500 opacity-60 hover:opacity-100 hover:bg-zinc-800/40'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-xs shrink-0">{agent.icon}</span>
                      <span className="truncate text-xs font-medium">{agent.name}</span>
                    </div>
                    <div className={`w-7 h-4 rounded-full p-0.5 transition-colors shrink-0 ${isEnabled ? 'bg-purple-600' : 'bg-zinc-700'}`}>
                      <div className={`w-3 h-3 rounded-full bg-white transition-transform ${isEnabled ? 'translate-x-3' : 'translate-x-0'}`} />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Bottom */}
        <div className="px-2 pb-3 border-t border-zinc-800/60 pt-2 shrink-0">
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
