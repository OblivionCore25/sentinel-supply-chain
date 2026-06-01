import { useWebSocket } from '../hooks/useData';
import { severityClass, formatScore, severityFromScore } from '../utils/helpers';

export default function TimelinePage() {
  const { riskScores, alerts, isConnected } = useWebSocket();

  // Merge and sort by most recent
  const events = [
    ...riskScores.map((s, i) => ({ type: 'RISK_SCORE' as const, data: s, key: `score-${i}`, time: s.scoredAt })),
    ...alerts.map((a, i) => ({ type: 'ALERT' as const, data: a, key: `alert-${i}`, time: a.createdAt })),
  ].sort((a, b) => {
    if (!a.time && !b.time) return 0;
    if (!a.time) return 1;
    if (!b.time) return -1;
    return new Date(b.time).getTime() - new Date(a.time).getTime();
  });

  return (
    <div className="page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-lg)' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Event Timeline</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-muted)' }}>
          <span className={`status-dot ${isConnected ? 'online' : 'offline'}`} />
          {isConnected ? 'Streaming live events' : 'Disconnected'}
        </div>
      </div>

      {events.length > 0 ? (
        <div style={{ position: 'relative', paddingLeft: '32px' }}>
          {/* Timeline line */}
          <div style={{
            position: 'absolute', left: '11px', top: '8px', bottom: '8px',
            width: '2px', background: 'var(--border-default)'
          }} />

          {events.map((event) => (
            <div key={event.key} style={{
              position: 'relative', marginBottom: 'var(--space-md)',
              animation: 'fadeSlideIn 0.3s ease forwards'
            }}>
              {/* Timeline dot */}
              <div style={{
                position: 'absolute', left: '-26px', top: '12px',
                width: '12px', height: '12px', borderRadius: '50%',
                background: event.type === 'ALERT' ? 'var(--severity-critical)' : 'var(--accent-cyan)',
                border: '2px solid var(--bg-primary)',
                boxShadow: event.type === 'ALERT'
                  ? '0 0 8px var(--severity-critical)'
                  : '0 0 8px var(--accent-cyan)',
              }} />

              <div className="card" style={{
                borderLeftWidth: '3px',
                borderLeftColor: event.type === 'ALERT' ? 'var(--severity-critical)' : 'var(--accent-cyan)',
              }}>
                {event.type === 'RISK_SCORE' ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div className={`risk-score ${severityClass(severityFromScore(event.data.score))}`} style={{
                      width: '40px', height: '40px', fontSize: '13px'
                    }}>
                      {formatScore(event.data.score)}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '14px' }}>
                        Risk Score: {event.data.cveId}
                      </div>
                      <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        Project: {event.data.projectName ?? event.data.projectId} ·
                        Depth: {event.data.transitiveDepth} ·
                        Paths: {event.data.pathCount}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <span style={{ fontSize: '24px' }}>🔔</span>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className={`severity-badge ${severityClass(event.data.severity)}`}>
                          {event.data.severity}
                        </span>
                        <span style={{ fontWeight: 600, fontSize: '14px' }}>{event.data.cveId}</span>
                      </div>
                      <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        {event.data.message ?? `${event.data.packageName} · Score: ${formatScore(event.data.riskScore)}`}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">📅</div>
            <div className="empty-state-text">
              {isConnected
                ? 'Waiting for events… Risk scores and alerts will appear here in real time.'
                : 'Connect to the live feed to see real-time events.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
