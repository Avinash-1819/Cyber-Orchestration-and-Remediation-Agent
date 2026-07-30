import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Send, Square, Shield, Zap, CheckCircle, XCircle, Clock, Download, Loader2,
  Bug, ChevronDown, ChevronUp, LayoutGrid, MessageSquare
} from 'lucide-react';

const API = 'http://localhost:8000/api/v1';
const WS_BASE = 'ws://localhost:8000/api/v1';

// ─── Types ───────────────────────────────────────────────────────────────────

interface WsEvent {
  type: string;
  agent?: string;
  session_id?: string;
  pipeline?: string;
  confidence?: number;
  finding_count?: number;
  error?: string;
  question?: string;
}

interface AgentStep {
  name: string;
  status: 'idle' | 'running' | 'done' | 'error';
  findings?: number;
}

interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  ts: number;
  sessionId?: string;
  pipeline?: string;
  agents?: AgentStep[];
  status?: 'thinking' | 'streaming' | 'done' | 'error';
  findings?: any[];
  selectedAgents?: string[];
}

// ─── Scanner / Service Definitions ───────────────────────────────────────────

const SERVICES = [
  {
    id: 'sast',
    icon: '🛡️',
    label: 'SAST Code Scanner',
    desc: 'Detect SQLi, XSS, secrets, insecure patterns in source code',
    agents: ['DevSecOpsAgent'],
    hint: 'CODE',
    color: 'blue',
    example: 'Paste Python/JS/Java/Go source code here...',
  },
  {
    id: 'docker',
    icon: '🐳',
    label: 'Dockerfile Auditor',
    desc: 'Detect privileged containers, latest tags, secret leaks in Dockerfiles',
    agents: ['DevSecOpsAgent'],
    hint: 'CODE',
    color: 'cyan',
    example: 'FROM ubuntu:latest\nRUN apt-get install ...',
  },
  {
    id: 'iac',
    icon: '🏗️',
    label: 'Terraform / IaC Analyzer',
    desc: 'Detect IAM misconfigs, open security groups, public S3 buckets',
    agents: ['DevSecOpsAgent', 'ComplianceAgent'],
    hint: 'CODE',
    color: 'amber',
    example: 'resource "aws_security_group" "allow_all" { ... }',
  },
  {
    id: 'triage',
    icon: '📊',
    label: 'Incident Triage Engine',
    desc: 'Classify logs, extract IOCs, enrich via VirusTotal/Shodan',
    agents: ['IncidentTriageAgent', 'RemediationAgent'],
    hint: 'LOGS',
    color: 'red',
    example: 'Jul 29 14:33 sshd: Failed password for root from 185.220.101.47',
  },
  {
    id: 'enricher',
    icon: '🔍',
    label: 'Threat Enricher',
    desc: 'Enrich IPs, domains, hashes via VirusTotal & Shodan',
    agents: ['IncidentTriageAgent', 'ThreatIntelAgent'],
    hint: 'IOC',
    color: 'purple',
    example: '185.220.101.47\nmalware.example.com\nabc123def...',
  },
  {
    id: 'compliance',
    icon: '📜',
    label: 'GRC Compliance Mapper',
    desc: 'Map findings to ISO 27001, SOC 2, NIST SP 800-53, PCI DSS 4.0',
    agents: ['ComplianceAgent', 'ExecReportingAgent'],
    hint: 'CODE',
    color: 'green',
    example: 'Paste code or infrastructure config for compliance audit...',
  },
  {
    id: 'cve',
    icon: '🎯',
    label: 'CVE & ATT&CK Intelligence',
    desc: 'Live NVD CVE lookup, MITRE ATT&CK mapping, Sigma/YARA rules',
    agents: ['ThreatIntelAgent'],
    hint: 'CVE',
    color: 'orange',
    example: 'CVE-2024-3400\nCVE-2023-44487',
  },
  {
    id: 'report',
    icon: '📄',
    label: 'Executive PDF Report',
    desc: 'Generate full PDF/Markdown/JSON security report from any input',
    agents: ['IncidentTriageAgent', 'DevSecOpsAgent', 'ThreatIntelAgent', 'ExecReportingAgent'],
    hint: 'MIXED',
    color: 'violet',
    example: 'Paste any security data for full executive reporting...',
  },
];

const ALL_AGENTS = [
  { name: 'IncidentTriageAgent', icon: '🔍', label: 'Incident Triage' },
  { name: 'RemediationAgent', icon: '⚡', label: 'Remediation' },
  { name: 'DevSecOpsAgent', icon: '🛡️', label: 'DevSecOps' },
  { name: 'ComplianceAgent', icon: '📋', label: 'Compliance' },
  { name: 'ThreatIntelAgent', icon: '🧠', label: 'Threat Intel' },
  { name: 'ExecReportingAgent', icon: '📊', label: 'Exec Report' },
];

const PIPELINE_AGENTS: Record<string, string[]> = {
  A: ['DevSecOpsAgent', 'ComplianceAgent', 'ExecReportingAgent'],
  B: ['IncidentTriageAgent', 'RemediationAgent', 'ThreatIntelAgent', 'ExecReportingAgent'],
  C: ['ThreatIntelAgent', 'ExecReportingAgent'],
  A_THEN_B: ['DevSecOpsAgent', 'ComplianceAgent', 'IncidentTriageAgent', 'RemediationAgent', 'ThreatIntelAgent', 'ExecReportingAgent'],
  CUSTOM: [],
};

const COLOR_MAP: Record<string, string> = {
  blue: 'border-blue-600/40 bg-blue-900/10 hover:bg-blue-900/20',
  cyan: 'border-cyan-600/40 bg-cyan-900/10 hover:bg-cyan-900/20',
  amber: 'border-amber-600/40 bg-amber-900/10 hover:bg-amber-900/20',
  red: 'border-red-600/40 bg-red-900/10 hover:bg-red-900/20',
  purple: 'border-purple-600/40 bg-purple-900/10 hover:bg-purple-900/20',
  green: 'border-green-600/40 bg-green-900/10 hover:bg-green-900/20',
  orange: 'border-orange-600/40 bg-orange-900/10 hover:bg-orange-900/20',
  violet: 'border-violet-600/40 bg-violet-900/10 hover:bg-violet-900/20',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function renderMarkdown(md: string): string {
  if (!md) return '';
  return md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/```[\w]*\n([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    .replace(/^\- (.+)$/gm, '<li>$1</li>')
    .replace(/^\> (.+)$/gm, '<blockquote>$1</blockquote>')
    .replace(/\n/g, '<br/>');
}

function SevBadge({ sev }: { sev: string }) {
  const m: Record<string, string> = {
    CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium',
    LOW: 'sev-low', INFORMATIONAL: 'sev-info',
  };
  return <span className={`text-xs px-2 py-0.5 rounded font-mono font-semibold ${m[sev] || 'sev-info'}`}>{sev}</span>;
}

function AgentTimeline({ agents }: { agents: AgentStep[] }) {
  return (
    <div className="flex flex-col gap-1.5 mt-3">
      {agents.map((a) => (
        <div key={a.name} className="flex items-center gap-2.5">
          <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs shrink-0
            ${a.status === 'running' ? 'agent-active bg-purple-900/40' :
              a.status === 'done' ? 'agent-done bg-emerald-900/40' :
              a.status === 'error' ? 'agent-error bg-red-900/40' : 'bg-zinc-800'}`}>
            {ALL_AGENTS.find(ag => ag.name === a.name)?.icon || '🤖'}
          </div>
          <span className={`text-xs font-mono flex-1 ${
            a.status === 'running' ? 'text-purple-300' :
            a.status === 'done' ? 'text-emerald-400' :
            a.status === 'error' ? 'text-red-400' : 'text-zinc-500'}`}>
            {a.name}
            {a.findings !== undefined && a.status === 'done' && (
              <span className="text-zinc-500 ml-2">{a.findings} findings</span>
            )}
          </span>
          {a.status === 'running' && (
            <span className="flex gap-0.5">
              <span className="typing-dot" /><span className="typing-dot" /><span className="typing-dot" />
            </span>
          )}
          {a.status === 'done' && <CheckCircle className="w-3 h-3 text-emerald-400 shrink-0" />}
          {a.status === 'running' && <Loader2 className="w-3 h-3 text-purple-400 animate-spin shrink-0" />}
          {a.status === 'error' && <XCircle className="w-3 h-3 text-red-400 shrink-0" />}
          {a.status === 'idle' && <Clock className="w-3 h-3 text-zinc-600 shrink-0" />}
        </div>
      ))}
    </div>
  );
}

function MessageBubble({ msg, token }: { msg: Message; token: string | null }) {
  const [findingsOpen, setFindingsOpen] = useState(false);

  const downloadReport = (format: string) => {
    if (!msg.sessionId || !token) return;
    fetch(`${API}/reports/${msg.sessionId}/${format}`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.blob()).then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `core-report-${msg.sessionId?.slice(0, 8)}.${format}`;
        a.click();
      });
  };

  if (msg.role === 'user') {
    return (
      <div className="flex justify-end mb-4 msg-appear">
        <div className="max-w-2xl">
          <div className="bg-purple-700/25 border border-purple-600/30 rounded-2xl rounded-tr-sm px-4 py-3">
            <p className="text-sm text-gray-100 whitespace-pre-wrap leading-relaxed">{msg.content}</p>
          </div>
          {msg.selectedAgents && msg.selectedAgents.length > 0 && (
            <div className="flex gap-1 mt-1.5 justify-end flex-wrap">
              {msg.selectedAgents.map(a => (
                <span key={a} className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full border border-zinc-700">
                  {ALL_AGENTS.find(ag => ag.name === a)?.icon} {ALL_AGENTS.find(ag => ag.name === a)?.label || a}
                </span>
              ))}
            </div>
          )}
          <div className="text-right mt-1">
            <span className="text-xs text-zinc-500">{new Date(msg.ts).toLocaleTimeString()}</span>
          </div>
        </div>
      </div>
    );
  }

  if (msg.role === 'system') {
    return (
      <div className="flex justify-center mb-3 msg-appear">
        <span className="text-xs text-zinc-500 bg-zinc-800/50 px-3 py-1 rounded-full border border-zinc-700/50">{msg.content}</span>
      </div>
    );
  }

  return (
    <div className="flex gap-3 mb-4 msg-appear">
      <div className="w-8 h-8 rounded-full bg-purple-700/40 border border-purple-600/50 flex items-center justify-center shrink-0 mt-0.5">
        <Shield className="w-4 h-4 text-purple-300" />
      </div>
      <div className="flex-1 min-w-0">
        {msg.status === 'thinking' && (
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs text-purple-400 font-mono">CORE is analyzing</span>
            <span className="flex gap-0.5"><span className="typing-dot" /><span className="typing-dot" /><span className="typing-dot" /></span>
          </div>
        )}

        {msg.pipeline && (
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className="text-xs bg-purple-900/40 border border-purple-700/40 text-purple-300 px-2.5 py-0.5 rounded-full font-mono">
              Pipeline {msg.pipeline}
            </span>
          </div>
        )}

        {msg.agents && msg.agents.length > 0 && (
          <div className="glass rounded-xl p-3 mb-3 border border-zinc-700/40">
            <div className="text-xs text-zinc-400 font-mono mb-2 flex items-center gap-1.5">
              <Zap className="w-3 h-3 text-purple-400" />AGENT PIPELINE
            </div>
            <AgentTimeline agents={msg.agents} />
          </div>
        )}

        {msg.content && (
          <div className="glass rounded-xl rounded-tl-sm p-4 border border-zinc-700/40">
            <div className="ai-content text-sm leading-relaxed text-gray-200"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
          </div>
        )}

        {msg.findings && msg.findings.length > 0 && (
          <div className="mt-2 glass rounded-xl border border-zinc-700/40">
            <button
              onClick={() => setFindingsOpen(!findingsOpen)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-sm"
            >
              <div className="flex items-center gap-2">
                <Bug className="w-3.5 h-3.5 text-amber-400" />
                <span className="font-mono text-zinc-300">
                  {msg.findings.length} FINDINGS
                  {msg.findings.filter(f => f.severity === 'CRITICAL').length > 0 &&
                    <span className="ml-2 text-red-400">🔴{msg.findings.filter(f => f.severity === 'CRITICAL').length} CRITICAL</span>}
                  {msg.findings.filter(f => f.severity === 'HIGH').length > 0 &&
                    <span className="ml-2 text-orange-400">🟠{msg.findings.filter(f => f.severity === 'HIGH').length} HIGH</span>}
                </span>
              </div>
              {findingsOpen ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
            </button>
            {findingsOpen && (
              <div className="border-t border-zinc-700/40 p-3 flex flex-col gap-2">
                {msg.findings.map((f: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 p-2.5 bg-zinc-800/50 rounded-lg">
                    <SevBadge sev={f.severity || 'INFO'} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-gray-200 font-medium">{f.title}</p>
                      <p className="text-xs text-zinc-400 mt-0.5 leading-relaxed">{f.description?.slice(0, 180)}{f.description?.length > 180 ? '...' : ''}</p>
                      {f.remediation_advice && (
                        <p className="text-xs text-emerald-400 mt-1">→ {f.remediation_advice?.slice(0, 120)}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {msg.sessionId && msg.status === 'done' && (
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className="text-xs text-zinc-500">Download:</span>
            {['pdf', 'markdown', 'json'].map(fmt => (
              <button key={fmt} onClick={() => downloadReport(fmt)}
                className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300 bg-purple-900/20 hover:bg-purple-900/40 border border-purple-700/30 px-2.5 py-1 rounded-lg transition-all">
                <Download className="w-3 h-3" />{fmt.toUpperCase()}
              </button>
            ))}
          </div>
        )}

        <div className="mt-1.5">
          <span className="text-xs text-zinc-500">{new Date(msg.ts).toLocaleTimeString()}</span>
        </div>
      </div>
    </div>
  );
}

// ─── Service Selector Panel ────────────────────────────────────────────────────

function ServiceSelector({
  selectedServiceId, onSelect, onClose,
}: {
  selectedServiceId: string | null;
  onSelect: (service: typeof SERVICES[0]) => void;
  onClose: () => void;
}) {
  return (
    <div className="border-b border-zinc-800/60 bg-[#0d0d14]/95 px-4 py-3">
      <div className="max-w-3xl mx-auto">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <LayoutGrid className="w-4 h-4 text-purple-400" />
            <span className="text-sm font-semibold text-gray-200">Select a Scanner</span>
            <span className="text-xs text-zinc-500">— or use Auto Mode for full orchestration</span>
          </div>
          <button onClick={onClose} className="text-xs text-zinc-500 hover:text-zinc-300 bg-zinc-800 px-2 py-1 rounded-lg transition-colors">
            ✕ Close
          </button>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {SERVICES.map(s => (
            <button
              key={s.id}
              onClick={() => onSelect(s)}
              className={`flex flex-col items-start gap-1 p-3 rounded-xl border text-left transition-all ${
                selectedServiceId === s.id
                  ? 'border-purple-600/80 bg-purple-900/30 shadow-lg shadow-purple-900/20'
                  : COLOR_MAP[s.color] || 'border-zinc-700/40 bg-zinc-800/20 hover:bg-zinc-800/40'
              }`}
            >
              <span className="text-lg">{s.icon}</span>
              <span className="text-xs font-semibold text-gray-200 leading-tight">{s.label}</span>
              <span className="text-xs text-zinc-500 leading-tight line-clamp-2">{s.desc}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Main Agent Component ─────────────────────────────────────────────────────

export default function Agent() {
  const [messages, setMessages] = useState<Message[]>([{
    id: 'welcome',
    role: 'assistant',
    content: `Welcome to **CORE** — Cyber Orchestration and Remediation Engine.

I'm your autonomous multi-agent AI security platform powered by **6 specialized agents**:

| Agent | Capability |
|---|---|
| 🔍 Incident Triage | Parse logs, extract IOCs, VirusTotal/Shodan enrichment |
| ⚡ Remediation | Generate containment playbooks & mitigation commands |
| 🛡️ DevSecOps | SAST, secret detection, Dockerfile & Terraform audits |
| 📋 Compliance | ISO 27001, SOC 2, NIST SP 800-53, PCI DSS 4.0 mapping |
| 🧠 Threat Intel | NVD CVE lookup, MITRE ATT&CK, Sigma/YARA rule generation |
| 📊 Exec Reporting | PDF, Markdown & JSON security report generation |

**Auto Mode** — paste any security data and I classify + route automatically.
**Scanner Mode** — click the grid icon below to select a specific scanner or agent.`,
    ts: Date.now(),
    status: 'done',
  }]);
  const [input, setInput] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [token, setToken] = useState<string | null>(localStorage.getItem('core_token'));
  const [showServiceSelector, setShowServiceSelector] = useState(false);
  const [selectedService, setSelectedService] = useState<typeof SERVICES[0] | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 200) + 'px';
  };

  const getToken = useCallback(async (forceRefresh = false): Promise<string | null> => {
    if (!forceRefresh && token) return token;
    try {
      localStorage.removeItem('core_token');
      await fetch(`${API}/auth/local/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'core_admin', password: 'core_pass_2024!' })
      });
      const res = await fetch(`${API}/auth/local/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'core_admin', password: 'core_pass_2024!' })
      });
      if (res.ok) {
        const d = await res.json();
        localStorage.setItem('core_token', d.access_token);
        setToken(d.access_token);
        return d.access_token;
      }
    } catch { }
    return null;
  }, [token]);

  useEffect(() => { getToken(); }, []);

  const updateMessage = useCallback((id: string, patch: Partial<Message>) => {
    setMessages(prev => prev.map(m => m.id === id ? { ...m, ...patch } : m));
  }, []);

  const fetchFinalState = async (aiId: string, sid: string, tk: string) => {
    try {
      const [stateRes, findingsRes] = await Promise.all([
        fetch(`${API}/sessions/${sid}`, { headers: { Authorization: `Bearer ${tk}` } }),
        fetch(`${API}/incidents/${sid}/findings`, { headers: { Authorization: `Bearer ${tk}` } }),
      ]);
      const state = stateRes.ok ? await stateRes.json() : null;
      const findingsData = findingsRes.ok ? await findingsRes.json() : null;
      const findings = findingsData?.findings || [];
      const s = state?.state || {};
      const es = s.executive_summary || {};

      let content = '';
      if (es.overview) content += es.overview + '\n\n';
      else if (s.threat_intel_report?.threat_summary) content += s.threat_intel_report.threat_summary + '\n\n';
      else if (s.triage_report?.executive_one_liner) content += s.triage_report.executive_one_liner + '\n\n';
      else if (s.code_audit_report?.audit_summary) content += s.code_audit_report.audit_summary + '\n\n';

      const crit = findings.filter((f: any) => f.severity === 'CRITICAL').length;
      const high = findings.filter((f: any) => f.severity === 'HIGH').length;
      const med = findings.filter((f: any) => f.severity === 'MEDIUM').length;

      if (findings.length > 0) {
        content += `**Risk Summary:** ${crit > 0 ? `🔴 ${crit} Critical  ` : ''}${high > 0 ? `🟠 ${high} High  ` : ''}${med > 0 ? `🟡 ${med} Medium  ` : ''}— **${findings.length} total findings**`;
      } else {
        content += '✅ **No security issues detected.** Analysis completed cleanly.';
      }

      if (es.recommendations?.length) {
        content += '\n\n**Top Recommendations:**\n' + es.recommendations.slice(0, 3).map((r: string) => `→ ${r}`).join('\n');
      }

      updateMessage(aiId, { status: 'done', content, findings });
    } catch {
      updateMessage(aiId, { status: 'done', content: '✅ Analysis complete. Download the report below.' });
    }
  };

  const send = useCallback(async () => {
    const text = input.trim();
    if (!text || isRunning) return;

    setInput('');
    if (textareaRef.current) textareaRef.current.style.height = 'auto';

    const isCustom = !!selectedService;
    const agentsToRun = selectedService?.agents;

    const userMsg: Message = {
      id: `u-${Date.now()}`, role: 'user', content: text, ts: Date.now(),
      selectedAgents: agentsToRun,
    };
    const aiId = `a-${Date.now()}`;
    const aiMsg: Message = {
      id: aiId, role: 'assistant', content: '', ts: Date.now(),
      status: 'thinking', agents: [],
    };

    setMessages(prev => [...prev, userMsg, aiMsg]);
    setIsRunning(true);

    try {
      let tk = await getToken();
      if (!tk) throw new Error('Could not authenticate with backend. Is it running?');

      const body: any = {
        input: text,
        input_type_hint: selectedService?.hint || undefined,
      };
      if (isCustom && agentsToRun) {
        body.mode = 'custom';
        body.selected_agents = agentsToRun;
      } else {
        body.mode = 'auto';
      }

      let res = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tk}` },
        body: JSON.stringify(body),
      });

      // Handle token expiration transparently
      if (res.status === 401) {
        tk = await getToken(true);
        if (tk) {
          res = await fetch(`${API}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tk}` },
            body: JSON.stringify(body),
          });
        }
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        const detail = err.detail;
        const msg = Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join('; ')
          : (typeof detail === 'string' ? detail : `HTTP ${res.status}`);
        throw new Error(msg);
      }

      const scanData = await res.json();
      const sid = scanData.session_id;
      updateMessage(aiId, { sessionId: sid, status: 'streaming' });

      // Connect WebSocket
      const ws = new WebSocket(`${WS_BASE}/ws/${sid}?token=${tk}`);
      wsRef.current = ws;
      let agentNames: string[] = [];

      ws.onmessage = (ev) => {
        try {
          const event: WsEvent = JSON.parse(ev.data);
          if (event.type === 'ping') return;

          setMessages(prev => prev.map(m => {
            if (m.id !== aiId) return m;
            const updates: Partial<Message> = {};

            if (event.type === 'classified') {
              const p = event.pipeline || 'B';
              agentNames = isCustom && agentsToRun
                ? [...agentsToRun, ...(agentsToRun.includes('ExecReportingAgent') ? [] : ['ExecReportingAgent'])]
                : (PIPELINE_AGENTS[p] || PIPELINE_AGENTS.B);
              updates.pipeline = p;
              updates.agents = agentNames.map(name => ({ name, status: 'idle' as const }));
            } else if (event.type === 'agent_started') {
              updates.agents = (m.agents || []).map(a =>
                a.name === event.agent ? { ...a, status: 'running' as const } : a);
            } else if (event.type === 'agent_completed') {
              updates.agents = (m.agents || []).map(a =>
                a.name === event.agent ? { ...a, status: 'done' as const, findings: event.finding_count } : a);
              if (event.agent === 'ExecReportingAgent') {
                ws.close();
                fetchFinalState(aiId, sid, tk!);
              }
            } else if (event.type === 'agent_error') {
              updates.agents = (m.agents || []).map(a =>
                a.name === event.agent ? { ...a, status: 'error' as const } : a);
            }
            return { ...m, ...updates };
          }));
        } catch { }
      };

      ws.onerror = () => {
        updateMessage(aiId, { status: 'error', content: '⚠️ WebSocket connection error.' });
        setIsRunning(false);
      };
      ws.onclose = () => { setIsRunning(false); };

    } catch (err: any) {
      updateMessage(aiId, {
        status: 'error',
        content: `❌ **Error:** ${String(err?.message || err)}\n\nPlease verify backend is running at \`http://localhost:8000\``,
      });
      setIsRunning(false);
    }
  }, [input, isRunning, selectedService, getToken, updateMessage]);

  const handleServiceSelect = (service: typeof SERVICES[0]) => {
    setSelectedService(service);
    setShowServiceSelector(false);
    setInput(service.example);
    setTimeout(() => textareaRef.current?.focus(), 100);
  };

  const clearService = () => {
    setSelectedService(null);
    setInput('');
    if (textareaRef.current) textareaRef.current.style.height = 'auto';
  };

  const stopScan = () => {
    wsRef.current?.close();
    setIsRunning(false);
    setMessages(prev => prev.map(m =>
      m.status === 'streaming' || m.status === 'thinking'
        ? { ...m, status: 'done', content: m.content || 'Analysis stopped by user.' } : m
    ));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Mode toggle header */}
      <div className="border-b border-zinc-800/60 bg-[#0d0d14]/80 px-4 py-2 flex items-center gap-3">
        <div className="flex items-center gap-2 bg-zinc-800/60 rounded-lg p-1">
          <button
            onClick={clearService}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              !selectedService ? 'bg-purple-700 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'}`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            Auto Orchestration
          </button>
          <button
            onClick={() => setShowServiceSelector(!showServiceSelector)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              selectedService || showServiceSelector ? 'bg-purple-700 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'}`}
          >
            <LayoutGrid className="w-3.5 h-3.5" />
            Scanner Mode
          </button>
        </div>

        {selectedService && (
          <div className="flex items-center gap-2 bg-zinc-800/60 border border-zinc-700/60 rounded-lg px-3 py-1.5">
            <span className="text-sm">{selectedService.icon}</span>
            <span className="text-xs font-medium text-gray-300">{selectedService.label}</span>
            <button onClick={clearService} className="text-zinc-500 hover:text-zinc-300 ml-1 text-xs">✕</button>
          </div>
        )}

        {!selectedService && (
          <span className="text-xs text-zinc-500">
            CORE automatically classifies your input and routes it to the right agents
          </span>
        )}
      </div>

      {/* Service selector panel */}
      {showServiceSelector && (
        <ServiceSelector
          selectedServiceId={selectedService?.id || null}
          onSelect={handleServiceSelect}
          onClose={() => setShowServiceSelector(false)}
        />
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto">
          {messages.map(msg => <MessageBubble key={msg.id} msg={msg} token={token} />)}
          <div ref={bottomRef} />
        </div>
      </div>

      {/* Input bar */}
      <div className="border-t border-zinc-800/60 bg-[#0a0a0f]/95 backdrop-blur px-4 py-4">
        <div className="max-w-3xl mx-auto">
          {selectedService && (
            <div className="mb-2 flex items-center gap-2 text-xs text-zinc-400">
              <span className="text-base">{selectedService.icon}</span>
              <span className="font-medium text-gray-300">{selectedService.label}</span>
              <span className="text-zinc-600">•</span>
              <span>Agents: {selectedService.agents.map(a => ALL_AGENTS.find(ag => ag.name === a)?.label || a).join(' → ')}</span>
            </div>
          )}
          <div className="flex items-end gap-3 glass rounded-2xl border border-zinc-700/60 px-4 py-3 focus-within:border-purple-600/60 transition-colors">
            <button
              onClick={() => setShowServiceSelector(!showServiceSelector)}
              title="Select scanner"
              className="shrink-0 mb-0.5 text-zinc-500 hover:text-purple-400 transition-colors"
            >
              <LayoutGrid className="w-5 h-5" />
            </button>
            <textarea
              ref={textareaRef}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              disabled={isRunning}
              rows={1}
              placeholder={selectedService
                ? `Paste ${selectedService.label.toLowerCase()} input here...`
                : 'Paste security logs, source code, CVE IDs, IPs, or ask a security question...'}
              className="flex-1 bg-transparent text-sm text-gray-200 placeholder-zinc-500 resize-none outline-none min-h-[24px] max-h-[200px] leading-relaxed font-sans disabled:opacity-50"
            />
            <button
              onClick={isRunning ? stopScan : send}
              disabled={!input.trim() && !isRunning}
              className={`shrink-0 w-9 h-9 rounded-xl flex items-center justify-center transition-all ${
                isRunning ? 'bg-red-600/80 hover:bg-red-500 text-white' :
                input.trim() ? 'bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-900/30' :
                'bg-zinc-700 text-zinc-500 cursor-not-allowed'}`}
            >
              {isRunning ? <Square className="w-4 h-4" /> : <Send className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-center text-xs text-zinc-600 mt-2">
            <kbd className="bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400 font-mono text-xs">Enter</kbd> to send ·{' '}
            <kbd className="bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400 font-mono text-xs">Shift+Enter</kbd> for newline ·{' '}
            <kbd className="bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400 font-mono text-xs">⊞</kbd> for scanner selection
          </p>
        </div>
      </div>
    </div>
  );
}
