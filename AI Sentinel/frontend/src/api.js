const BASE_URL = '/api';
const TOKEN_KEY = 'ai_sentinel_token';

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function isAuthenticated() {
  return Boolean(getToken());
}

export function getRole() {
  return localStorage.getItem('ai_sentinel_role') || '';
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem('ai_sentinel_role');
  window.location.href = '/login';
}

async function request(path, options = {}, requiresAuth = true) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (requiresAuth && getToken()) {
    headers.Authorization = `Bearer ${getToken()}`;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    logout();
    throw new Error('Session expired. Please log in again.');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail = err.detail;
    const message = typeof detail === 'string' ? detail : (detail && detail.msg) || 'Request failed';
    throw new Error(message);
  }

  return res.json();
}

export async function loginUser(username, password) {
  const data = await request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }, false);
  setToken(data.token);
  localStorage.setItem('ai_sentinel_role', data.role || '');
  return data;
}

export async function getMe() {
  return request('/auth/me');
}

export async function changePassword(current_password, new_password) {
  return request('/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) });
}

export async function listUsers() {
  return request('/auth/users');
}

export async function createUser(payload) {
  return request('/auth/users', { method: 'POST', body: JSON.stringify(payload) });
}

export async function getOverview() {
  return request('/overview');
}

export async function listEvents(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/events/?${q.toString()}`);
}

export async function getEvent(id) {
  return request(`/events/${id}`);
}

export async function ingestEvents(events) {
  return request('/events/ingest', { method: 'POST', body: JSON.stringify({ events }) });
}

export async function listAlerts(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/alerts/?${q.toString()}`);
}

export async function updateAlert(id, payload) {
  return request(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(payload) });
}

export async function listIncidents(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/incidents/?${q.toString()}`);
}

export async function getIncident(id) {
  return request(`/incidents/${id}`);
}

export async function updateIncident(id, payload) {
  return request(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(payload) });
}

export async function respondToIncident(id, action, reason = '') {
  return request(`/incidents/${id}/respond`, { method: 'POST', body: JSON.stringify({ action, reason }) });
}

export async function getIncidentActions(id) {
  return request(`/incidents/${id}/actions`);
}

export async function getResponsePolicies() {
  return request('/incidents/policies/available');
}

export async function getTraffic() {
  return request('/network/traffic');
}

export async function getNetworkConnections() {
  return request('/network/connections');
}

export async function getNetworkTop() {
  return request('/network/top');
}

export async function getServers() {
  return request('/network/servers');
}

export async function listRules() {
  return request('/rules/');
}

export async function createRule(payload) {
  return request('/rules/', { method: 'POST', body: JSON.stringify(payload) });
}

export async function deleteRule(id) {
  return request(`/rules/${id}`, { method: 'DELETE' });
}

export async function testRule(id, params = {}) {
  return request(`/rules/${id}/test`, { method: 'POST', body: JSON.stringify(params) });
}

export async function ruleHistory(id) {
  return request(`/rules/${id}/history`);
}

export async function rollbackRule(id, version) {
  return request(`/rules/${id}/rollback`, { method: 'POST', body: JSON.stringify({ version }) });
}

export async function toggleRule(id) {
  return request(`/rules/${id}/toggle`, { method: 'POST' });
}

export async function updateRule(payload) {
  return request(`/rules/${payload.rule_id}`, { method: 'PUT', body: JSON.stringify(payload) });
}

export async function resetRules() {
  return request('/rules/reset', { method: 'POST' });
}

export async function listAgents() {
  return request('/agents/');
}

export async function getCollectorAgent() {
  return request('/agents/collector');
}

export async function updateUser(id, payload) {
  return request(`/auth/users/${id}`, { method: 'PATCH', body: JSON.stringify(payload) });
}

export async function analyzePhishing(url) {
  return request('/phishing/analyze', { method: 'POST', body: JSON.stringify({ url }) });
}

export async function listPhishingScans() {
  return request('/phishing/scans');
}

export async function getSystemAudit(limit = 100) {
  return request(`/system/audit?limit=${limit}`);
}

export async function getSystemHealth() {
  return request('/system/health');
}

export async function getSystemMetrics() {
  return request('/system/metrics');
}

export async function applyRetention() {
  return request('/system/retention/apply', { method: 'POST' });
}

export async function askChatbot(message) {
  return request('/chatbot/', { method: 'POST', body: JSON.stringify({ message }) });
}

export async function publicHealth() {
  return request('/health', {}, false);
}

export function wsUrl() {
  const base = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
  return `${base}${window.location.host}/ws/events?token=${encodeURIComponent(getToken())}`;
}
