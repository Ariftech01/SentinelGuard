const API_ROOT = `${process.env.REACT_APP_BACKEND_URL}/api`;

async function request(path: string, options: RequestInit = {}) {
  const res = await fetch(`${API_ROOT}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as any).detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export const api = {
  baseUrl: API_ROOT,
  getModels: () => request('/v1/models'),
  getModelAnalytics: () => request('/v1/analytics/models'),
  getDashboard: () => request('/v1/dashboard/stats'),
  getEvents: (search = '') => request(`/v1/events?search=${encodeURIComponent(search)}&limit=100`),
  secureChat: (body: { message: string; provider: string; model?: string; session_id: string }) =>
    request('/v1/secure/chat', { method: 'POST', body: JSON.stringify(body) }),
  getPolicies: () => request('/v1/policies'),
  createPolicy: (body: { name: string; when: string[]; risk: string; then: string }) =>
    request('/v1/policies', { method: 'POST', body: JSON.stringify(body) }),
  updatePolicy: (id: string, body: Record<string, unknown>) =>
    request(`/v1/policies/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  deletePolicy: (id: string) => request(`/v1/policies/${id}`, { method: 'DELETE' }),
  getAuditLogs: (params: { search?: string; action?: string; page?: number; page_size?: number }) => {
    const q = new URLSearchParams();
    if (params.search) q.set('search', params.search);
    if (params.action) q.set('action', params.action);
    q.set('page', String(params.page || 1));
    q.set('page_size', String(params.page_size || 10));
    return request(`/v1/audit-logs?${q.toString()}`);
  },
  getSettings: () => request('/v1/settings'),
  updateSettings: (body: Record<string, unknown>) =>
    request('/v1/settings', { method: 'PUT', body: JSON.stringify(body) }),
};
