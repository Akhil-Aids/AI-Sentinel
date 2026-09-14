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
  if (data.mfa_required) {
    return data; // second factor still pending
  }
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

export async function listHosts(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/hosts/?${q.toString()}`);
}

export async function getHost(hostname) {
  return request(`/hosts/${encodeURIComponent(hostname)}`);
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

// ---------- Reports ----------
export async function listReports(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/reports/?${q.toString()}`);
}

export async function createDailyReport(payload = {}) {
  return request('/reports/daily', { method: 'POST', body: JSON.stringify(payload) });
}

export async function createPostureReport() {
  return request('/reports/posture', { method: 'POST' });
}

export async function createIncidentReport(id) {
  return request(`/reports/incident/${encodeURIComponent(id)}`, { method: 'POST' });
}

export async function deleteReport(id) {
  return request(`/reports/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// ---------- Notifications ----------
export async function listNotifications() {
  return request('/notifications/');
}

export async function unreadNotifications() {
  return request('/notifications/unread-count');
}

export async function markNotificationRead(id) {
  return request(`/notifications/${encodeURIComponent(id)}/read`, { method: 'POST' });
}

export async function markAllNotificationsRead() {
  return request('/notifications/read-all', { method: 'POST' });
}

// ---------- Global search ----------
export async function globalSearch(q, limit = 5) {
  return request(`/search/?q=${encodeURIComponent(q)}&limit=${limit}`);
}

// ---------- Threat hunting ----------
export async function listHuntPatterns() {
  return request('/hunts/patterns');
}

export async function runHunt(filters, limit = 500) {
  return request('/hunts/run', { method: 'POST', body: JSON.stringify({ filters, limit }) });
}

export async function saveHunt(payload) {
  return request('/hunts/', { method: 'POST', body: JSON.stringify(payload) });
}

export async function listHunts() {
  return request('/hunts/');
}

export async function runSavedHunt(id) {
  return request(`/hunts/${encodeURIComponent(id)}/run`, { method: 'POST' });
}

export async function deleteHunt(id) {
  return request(`/hunts/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export async function huntHistory(id) {
  return request(`/hunts/${encodeURIComponent(id)}/history`);
}

// ---------- IOCs ----------
export async function listIocs(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/iocs/?${q.toString()}`);
}

export async function createIoc(payload) {
  return request('/iocs/', { method: 'POST', body: JSON.stringify(payload) });
}

export async function deleteIoc(id) {
  return request(`/iocs/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export async function updateIoc(id, payload) {
  return request(`/iocs/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) });
}

export async function getIocMatches(id) {
  return request(`/iocs/${encodeURIComponent(id)}/matches`);
}

// ---------- Approvals / workflow ----------
export async function listApprovals(status = '', limit = 100) {
  const q = new URLSearchParams({ limit });
  if (status) q.set('status', status);
  return request(`/approvals/?${q.toString()}`);
}

export async function getApproval(id) {
  return request(`/approvals/${encodeURIComponent(id)}`);
}

export async function approveApproval(id, reason = '') {
  return request(`/approvals/${encodeURIComponent(id)}/approve`, { method: 'POST', body: JSON.stringify({ reason }) });
}

export async function denyApproval(id, reason = '') {
  return request(`/approvals/${encodeURIComponent(id)}/deny`, { method: 'POST', body: JSON.stringify({ reason }) });
}

// ---------- Lifecycle history / notes ----------
export async function alertHistory(id) {
  return request(`/alerts/${encodeURIComponent(id)}/history`);
}

export async function addAlertNote(id, note) {
  return request(`/alerts/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ note }) });
}

export async function incidentHistory(id) {
  return request(`/incidents/${encodeURIComponent(id)}/history`);
}

export async function addIncidentNote(id, note) {
  return request(`/incidents/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ note }) });
}

export async function incidentRelated(id) {
  return request(`/incidents/${encodeURIComponent(id)}/related`);
}

// ---------- Risk insights ----------
export async function listUserRisks() {
  return request('/risks/users');
}

export async function listAssetRisks() {
  return request('/risks/assets');
}

export async function getUserRisk(username) {
  return request(`/risks/users/${encodeURIComponent(username)}`);
}

export async function getAssetRisk(hostname) {
  return request(`/risks/assets/${encodeURIComponent(hostname)}`);
}

// ---------- MFA ----------
export async function mfaStatus() {
  return request('/auth/mfa/status');
}

export async function mfaEnroll(password) {
  return request('/auth/mfa/enroll', { method: 'POST', body: JSON.stringify({ password }) });
}

export async function mfaConfirm(otp) {
  return request('/auth/mfa/confirm', { method: 'POST', body: JSON.stringify({ otp }) });
}

export async function mfaDisable(password, otp) {
  return request('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password, otp }) });
}

export async function mfaVerifyLogin(partialToken, otp) {
  return request('/auth/mfa/verify-login', { method: 'POST', body: JSON.stringify({ partial_token: partialToken, otp }) }, false);
}

// ---------- API keys ----------
export async function listApiKeys() {
  return request('/system/api-keys');
}

export async function createApiKey(payload) {
  return request('/system/api-keys', { method: 'POST', body: JSON.stringify(payload) });
}

export async function rotateApiKey(keyId) {
  return request(`/system/api-keys/${encodeURIComponent(keyId)}/rotate`, { method: 'POST' });
}

export async function revokeApiKey(keyId) {
  return request(`/system/api-keys/${encodeURIComponent(keyId)}/revoke`, { method: 'POST' });
}

// ---------- Cases ----------
export async function listCases(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/cases/?${q.toString()}`);
}

export async function getCase(id) {
  return request(`/cases/${encodeURIComponent(id)}`);
}

export async function createCase(payload) {
  return request('/cases/', { method: 'POST', body: JSON.stringify(payload) });
}

export async function updateCase(id, payload) {
  return request(`/cases/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(payload) });
}

export async function linkIncidentToCase(id, incidentId) {
  return request(`/cases/${encodeURIComponent(id)}/links`, { method: 'POST', body: JSON.stringify({ incident_id: incidentId }) });
}

export async function addCaseNote(id, note) {
  return request(`/cases/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ note }) });
}

// ---------- Evidence ----------
export async function listEvidence(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/evidence/?${q.toString()}`);
}

export async function createEvidence(payload) {
  return request('/evidence/', { method: 'POST', body: JSON.stringify(payload) });
}

export async function verifyEvidence(id) {
  return request(`/evidence/${encodeURIComponent(id)}/verify`, { method: 'POST' });
}

// ---------- SOC tasks ----------
export async function listTasks(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
  return request(`/tasks/?${q.toString()}`);
}

export async function createTask(payload) {
  return request('/tasks/', { method: 'POST', body: JSON.stringify(payload) });
}

export async function updateTask(id, payload) {
  return request(`/tasks/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(payload) });
}

// ---------- SLA ----------
export async function getSlaPolicies() {
  return request('/sla/policies/');
}

export async function updateSlaPolicy(severity, payload) {
  return request(`/sla/policies/${severity}`, { method: 'PUT', body: JSON.stringify(payload) });
}

export async function slaIncidents(limit = 200) {
  return request(`/sla/incidents/?limit=${limit}`);
}

// ---------- MITRE center ----------
export async function mitreCoverage() {
  return request('/mitre/coverage/');
}

export async function incidentReview(id) {
  return request(`/mitre/incidents/${encodeURIComponent(id)}/review`, { method: 'POST' });
}

// ---------- Posture ----------
export async function postureNow() {
  return request('/posture/now');
}

export async function postureHistory() {
  return request('/posture/history');
}

export async function postureRecord() {
  return request('/posture/record', { method: 'POST' });
}

// ---------- Data quality ----------
export async function dataQualityOverview() {
  return request('/data-quality/overview/');
}
