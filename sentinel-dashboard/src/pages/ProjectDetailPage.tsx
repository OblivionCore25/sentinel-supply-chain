import { useParams } from 'react-router-dom';
import { api, type Project, type RiskScore, type Alert } from '../services/api';
import { useFetch } from '../hooks/useData';
import { severityClass, formatScore, timeAgo, severityFromScore, truncate } from '../utils/helpers';
import { Link } from 'react-router-dom';

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const { data: project, loading: projectLoading } = useFetch<Project>(
    () => api.getProject(projectId!), [projectId]
  );
  const { data: riskScores, loading: scoresLoading } = useFetch<RiskScore[]>(
    () => api.getProjectRiskScores(projectId!), [projectId]
  );
  const { data: alerts } = useFetch<Alert[]>(
    () => api.getProjectAlerts(projectId!), [projectId]
  );

  if (projectLoading || scoresLoading) {
    return (
      <div className="page-enter" style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
        <div className="loading-spinner" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="page-enter">
        <div className="card empty-state">
          <div className="empty-state-icon">❌</div>
          <div className="empty-state-text">Project not found</div>
          <Link to="/" className="btn" style={{ marginTop: '16px' }}>← Back to Overview</Link>
        </div>
      </div>
    );
  }

  // Find highest risk score
  const maxScore = riskScores && riskScores.length > 0
    ? Math.max(...riskScores.map(s => s.score))
    : 0;

  return (
    <div className="page-enter">
      {/* Project Header */}
      <div style={{ marginBottom: 'var(--space-xl)' }}>
        <Link to="/" style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '8px', display: 'block' }}>
          ← Back to Overview
        </Link>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <h2 style={{ fontSize: '24px', fontWeight: 700 }}>{project.name}</h2>
          <span style={{
            fontSize: '12px', padding: '2px 10px',
            borderRadius: 'var(--radius-full)',
            background: project.ecosystem === 'MAVEN' ? 'var(--accent-blue-dim)' : 'var(--accent-emerald-dim)',
            color: project.ecosystem === 'MAVEN' ? 'var(--accent-blue)' : 'var(--accent-emerald)',
          }}>
            {project.ecosystem}
          </span>
        </div>
        {project.repositoryUrl && (
          <a href={project.repositoryUrl} target="_blank" rel="noopener noreferrer"
             style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>
            {project.repositoryUrl}
          </a>
        )}
      </div>

      {/* Stats */}
      <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <div className="stat-card" style={{ '--stat-accent': `var(--severity-${severityClass(severityFromScore(maxScore))})` } as React.CSSProperties}>
          <div className="stat-value" style={{ color: `var(--severity-${severityClass(severityFromScore(maxScore))})` }}>
            {formatScore(maxScore)}
          </div>
          <div className="stat-label">Highest Risk Score</div>
        </div>
        <div className="stat-card" style={{ '--stat-accent': 'var(--accent-purple)' } as React.CSSProperties}>
          <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>
            {riskScores?.length ?? 0}
          </div>
          <div className="stat-label">Active Vulnerabilities</div>
        </div>
        <div className="stat-card" style={{ '--stat-accent': 'var(--severity-critical)' } as React.CSSProperties}>
          <div className="stat-value" style={{ color: 'var(--severity-critical)' }}>
            {alerts?.length ?? 0}
          </div>
          <div className="stat-label">Unacknowledged Alerts</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-lg)' }}>
        {/* Risk Scores */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Risk Scores</span>
          </div>
          {riskScores && riskScores.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr><th>CVE</th><th>Score</th><th>Depth</th><th>Paths</th></tr>
              </thead>
              <tbody>
                {riskScores.map((score) => (
                  <tr key={score.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}>{score.cveId}</td>
                    <td>
                      <span style={{
                        fontWeight: 700,
                        color: `var(--severity-${severityClass(severityFromScore(score.score))})`,
                      }}>
                        {formatScore(score.score)}
                      </span>
                    </td>
                    <td>{score.transitiveDepth}</td>
                    <td>{score.pathCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">
              <div className="empty-state-text">No risk scores computed yet.</div>
            </div>
          )}
        </div>

        {/* Project Alerts */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Alerts</span>
          </div>
          {alerts && alerts.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {alerts.map((alert) => (
                <div key={alert.id} style={{
                  padding: '10px 12px', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-tertiary)', fontSize: '13px',
                  borderLeft: '3px solid var(--severity-critical)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span className={`severity-badge ${severityClass(alert.severity)}`} style={{ fontSize: '11px' }}>
                      {alert.severity}
                    </span>
                    <span style={{ fontWeight: 600 }}>{alert.cveId}</span>
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                    {truncate(alert.message, 120)} · {timeAgo(alert.createdAt)}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-text">No active alerts for this project.</div>
            </div>
          )}
        </div>
      </div>

      {/* Graph Link */}
      <div style={{ marginTop: 'var(--space-lg)' }}>
        <Link to={`/graph?project=${projectId}`} className="btn btn-primary">
          🕸️ View Dependency Graph
        </Link>
      </div>
    </div>
  );
}
