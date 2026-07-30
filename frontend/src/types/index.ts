export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

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
}
