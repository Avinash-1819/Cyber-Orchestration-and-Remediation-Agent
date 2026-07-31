import axios from 'axios';

const API_BASE = (import.meta.env.VITE_API_URL as string) || 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: API_BASE,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('core_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => Promise.reject(err)
);

export { API_BASE };

export function wsUrl(sessionId: string, token: string): string {
  const base = API_BASE.replace(/^http/, 'ws');
  return `${base}/ws/${sessionId}?token=${token}`;
}

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
};
