/**
 * PromptShield AI — API Client
 * Dynamically resolves backend endpoint for local dev or Render production deployments.
 */

const DEFAULT_API_URL = import.meta.env.VITE_BACKEND_URL || (window.location.hostname === 'localhost' ? 'http://localhost:8000' : '');

export function getBackendUrl() {
  const custom = localStorage.getItem('PROMPTSHIELD_BACKEND_URL');
  if (custom && custom.trim()) {
    return custom.trim().replace(/\/+$/, '');
  }
  return DEFAULT_API_URL;
}

export function setBackendUrl(url) {
  if (!url || !url.trim()) {
    localStorage.removeItem('PROMPTSHIELD_BACKEND_URL');
  } else {
    localStorage.setItem('PROMPTSHIELD_BACKEND_URL', url.trim().replace(/\/+$/, ''));
  }
}

async function request(path, options = {}) {
  const baseUrl = getBackendUrl();
  const url = `${baseUrl}${path}`;
  
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const res = await fetch(url, { ...options, headers });
    const contentType = res.headers.get('content-type') || '';
    let data;
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      data = { raw: await res.text() };
    }

    if (!res.ok) {
      const errorMsg = data?.detail || data?.message || `HTTP ${res.status}: ${res.statusText}`;
      throw new Error(typeof errorMsg === 'object' ? JSON.stringify(errorMsg) : errorMsg);
    }
    return data;
  } catch (err) {
    console.error(`API Error [${options.method || 'GET'} ${path}]:`, err);
    throw err;
  }
}

export const api = {
  getHealth: () => request('/api/v1/health'),
  getOverview: () => request('/api/v1/dashboard/overview'),
  
  getEvents: (params = {}) => {
    const query = new URLSearchParams();
    if (params.category && params.category !== 'ALL') query.set('category', params.category);
    if (params.limit) query.set('limit', params.limit);
    if (params.offset) query.set('offset', params.offset);
    const qs = query.toString();
    return request(`/api/v1/dashboard/events${qs ? `?${qs}` : ''}`);
  },

  getApprovals: (params = {}) => {
    const query = new URLSearchParams();
    if (params.status && params.status !== 'ALL') query.set('status', params.status);
    if (params.limit) query.set('limit', params.limit);
    if (params.offset) query.set('offset', params.offset);
    const qs = query.toString();
    return request(`/api/v1/dashboard/approvals${qs ? `?${qs}` : ''}`);
  },

  submitApprovalDecision: (approvalId, payload) =>
    request(`/api/v1/tools/approvals/${approvalId}/decision`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  analyzePrompt: (prompt, requesterId = 'dashboard-user') =>
    request('/api/v1/analyze', {
      method: 'POST',
      body: JSON.stringify({ prompt, requester_id: requesterId }),
    }),

  scanDocument: (documentId, content, source = 'user_upload') =>
    request('/api/v1/scan-document', {
      method: 'POST',
      body: JSON.stringify({ document_id: documentId, content, source }),
    }),

  getTools: () => request('/api/v1/tools'),

  authorizeTool: (payload) =>
    request('/api/v1/tools/authorize', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  executeTool: (payload) =>
    request('/api/v1/tools/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getBenchmarks: () => request('/api/v1/benchmarks'),
};
