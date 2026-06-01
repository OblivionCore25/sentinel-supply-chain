/**
 * API service for the Sentinel dashboard.
 * Communicates with the Analysis Service and Notification Service.
 */

const ANALYSIS_API = import.meta.env.VITE_ANALYSIS_API_URL || 'http://localhost:8082/api';
const NOTIFICATION_API = import.meta.env.VITE_NOTIFICATION_API_URL || 'http://localhost:8083/api';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

// ---- Types ----

export interface Project {
  id: string;
  name: string;
  repositoryUrl?: string;
  ecosystem: string;
  manifestPath?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Vulnerability {
  id: string;
  cveId: string;
  packageName: string;
  affectedRange: string;
  cvssScore: number;
  severity: string;
  description: string;
  publishedAt: string;
  source: string;
  createdAt: string;
}

export interface RiskScore {
  id: string;
  projectId: string;
  projectName?: string;
  vulnerabilityId: string;
  cveId: string;
  score: number;
  transitiveDepth: number;
  pathCount: number;
  scoredAt: string;
}

export interface Alert {
  id: string;
  projectId: string;
  vulnerabilityId: string;
  cveId: string;
  packageName: string;
  severity: string;
  message: string;
  riskScore: number;
  acknowledged: boolean;
  createdAt: string;
  acknowledgedAt?: string;
}

export interface DashboardSummary {
  totalProjects: number;
  totalVulnerabilities: number;
  unacknowledgedAlerts: number;
  projects: Array<{
    projectId: string;
    projectName: string;
    unacknowledgedAlerts: number;
  }>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphNode {
  id: string;
  packageName: string;
  version: string;
  ecosystem: string;
  direct: boolean;
  vulnerable: boolean;
  vulnerabilities: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
}

// ---- Analysis Service API ----

export const api = {
  // Projects
  getProjects: () => request<Project[]>(`${ANALYSIS_API}/projects`),
  getProject: (id: string) => request<Project>(`${ANALYSIS_API}/projects/${id}`),
  createProject: (data: Partial<Project>) =>
    request<Project>(`${ANALYSIS_API}/projects`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Risk Scores
  getProjectRiskScores: (projectId: string) =>
    request<RiskScore[]>(`${ANALYSIS_API}/projects/${projectId}/risk-scores`),
  getRiskScoreHistory: (projectId: string) =>
    request<RiskScore[]>(`${ANALYSIS_API}/projects/${projectId}/risk-scores/history`),

  // Alerts
  getAllAlerts: () => request<Alert[]>(`${ANALYSIS_API}/alerts`),
  getProjectAlerts: (projectId: string) =>
    request<Alert[]>(`${ANALYSIS_API}/projects/${projectId}/alerts`),
  acknowledgeAlert: (alertId: string) =>
    request<Alert>(`${ANALYSIS_API}/alerts/${alertId}/acknowledge`, { method: 'POST' }),

  // Vulnerabilities
  getVulnerabilities: () => request<Vulnerability[]>(`${ANALYSIS_API}/vulnerabilities`),
  getVulnerability: (cveId: string) =>
    request<Vulnerability>(`${ANALYSIS_API}/vulnerabilities/${cveId}`),

  // Graph
  getProjectGraph: (projectId: string) =>
    request<GraphData>(`${ANALYSIS_API}/projects/${projectId}/graph`),

  // Dashboard
  getDashboardSummary: () => request<DashboardSummary>(`${ANALYSIS_API}/dashboard/summary`),

  // Notification Service
  getRecentScores: (count = 20) =>
    request<RiskScore[]>(`${NOTIFICATION_API}/notifications/scores/recent?count=${count}`),
  getRecentAlerts: (count = 20) =>
    request<Alert[]>(`${NOTIFICATION_API}/notifications/alerts/recent?count=${count}`),
  getNotificationStatus: () =>
    request<{ service: string; status: string; activeWebSockets: number }>(
      `${NOTIFICATION_API}/notifications/status`
    ),
};
