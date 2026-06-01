import { api, type DashboardSummary, type Project, type Alert } from '../services/api';
import { useFetch, useWebSocket } from '../hooks/useData';
import { severityClass, formatScore, timeAgo, severityFromScore } from '../utils/helpers';
import { Link } from 'react-router-dom';

export default function OverviewPage() {
  const { data: summary, loading: summaryLoading } = useFetch<DashboardSummary>(api.getDashboardSummary);
  const { data: projects, loading: projectsLoading } = useFetch<Project[]>(api.getProjects);
  const { data: alerts } = useFetch<Alert[]>(api.getAllAlerts);
  const { riskScores: liveScores, isConnected } = useWebSocket();

  if (summaryLoading || projectsLoading) {
    return (
      <div className="page-enter" style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
        <div className="loading-spinner" />
      </div>
    );
  }

  return (
    <div className="page-enter">
      {/* Stats Grid */}
      <div className="stat-grid">
        <div className="stat-card" style={{ '--stat-accent': 'var(--accent-cyan)' } as React.CSSProperties}>
          <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>
            {summary?.totalProjects ?? 0}
          </div>
          <div className="stat-label">Monitored Projects</div>
        </div>

        <div className="stat-card" style={{ '--stat-accent': 'var(--accent-purple)' } as React.CSSProperties}>
          <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>
            {summary?.totalVulnerabilities ?? 0}
          </div>
          <div className="stat-label">Known Vulnerabilities</div>
        </div>

        <div className="stat-card" style={{ '--stat-accent': 'var(--severity-critical)' } as React.CSSProperties}>
          <div className="stat-value" style={{ color: 'var(--severity-critical)' }}>
            {summary?.unacknowledgedAlerts ?? 0}
          </div>
          <div className="stat-label">Active Alerts</div>
        </div>

        <div className="stat-card" style={{ '--stat-accent': 'var(--accent-emerald)' } as React.CSSProperties}>
          <div className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`status-dot ${isConnected ? 'online' : 'offline'}`} />
            <span style={{ color: isConnected ? 'var(--accent-emerald)' : 'var(--severity-critical)', fontSize: '18px' }}>
              {isConnected ? 'Connected' : 'Offline'}
            </span>
          </div>
          <div className="stat-label">Real-time Feed</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-lg)' }}>
        {/* Projects List */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Projects</span>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{projects?.length ?? 0} total</span>
          </div>
          {projects && projects.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Ecosystem</th>
                  <th>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {projects.map((project) => {
                  const alertCount = summary?.projects.find(p => p.projectId === project.id)?.unacknowledgedAlerts ?? 0;
                  return (
                    <tr key={project.id}>
                      <td>
                        <Link to={`/projects/${project.id}`} style={{ fontWeight: 500 }}>
                          {project.name}
                        </Link>
                      </td>
                      <td>
                        <span style={{
                          fontSize: '12px', padding: '2px 8px',
                          borderRadius: 'var(--radius-full)',
                          background: project.ecosystem === 'MAVEN' ? 'var(--accent-blue-dim)' : 'var(--accent-emerald-dim)',
                          color: project.ecosystem === 'MAVEN' ? 'var(--accent-blue)' : 'var(--accent-emerald)',
                        }}>
                          {project.ecosystem}
                        </span>
                      </td>
                      <td>
                        {alertCount > 0 ? (
                          <span className="severity-badge critical">{alertCount}</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">📦</div>
              <div className="empty-state-text">No projects registered yet. Add a project to start monitoring.</div>
            </div>
          )}
        </div>

        {/* Recent Activity */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent Activity</span>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Live feed</span>
          </div>
          {(liveScores.length > 0 || (alerts && alerts.length > 0)) ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '400px', overflowY: 'auto' }}>
              {/* Live risk scores */}
              {liveScores.slice(0, 10).map((score, i) => (
                <div key={`score-${i}`} style={{
                  display: 'flex', alignItems: 'center', gap: '12px',
                  padding: '10px 12px', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-tertiary)', fontSize: '13px',
                  animation: 'fadeSlideIn 0.3s ease forwards'
                }}>
                  <div className={`risk-score ${severityClass(severityFromScore(score.score))}`} style={{
                    width: '36px', height: '36px', fontSize: '13px', flexShrink: 0
                  }}>
                    {formatScore(score.score)}
                  </div>
                  <div>
                    <div style={{ fontWeight: 500 }}>{score.cveId}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                      Depth: {score.transitiveDepth} · Paths: {score.pathCount}
                    </div>
                  </div>
                </div>
              ))}

              {/* Persisted alerts */}
              {alerts?.slice(0, 5).map((alert) => (
                <div key={alert.id} style={{
                  display: 'flex', alignItems: 'center', gap: '12px',
                  padding: '10px 12px', borderRadius: 'var(--radius-md)',
                  background: 'var(--severity-critical-bg)', fontSize: '13px',
                  borderLeft: '3px solid var(--severity-critical)',
                }}>
                  <span>🔔</span>
                  <div>
                    <div style={{ fontWeight: 500, color: 'var(--severity-critical)' }}>{alert.cveId}</div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                      {alert.packageName} · {timeAgo(alert.createdAt)}
                    </div>
                  </div>
                </div>
              ))}

              {liveScores.length === 0 && (!alerts || alerts.length === 0) && (
                <div className="empty-state">
                  <div className="empty-state-text">Waiting for events…</div>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">📡</div>
              <div className="empty-state-text">No events yet. Connect to the live feed to see real-time updates.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
