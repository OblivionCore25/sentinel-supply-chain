import { api, type Alert } from '../services/api';
import { useFetch } from '../hooks/useData';
import { severityClass, formatScore, timeAgo, truncate } from '../utils/helpers';

export default function AlertsPage() {
  const { data: alerts, loading, refetch } = useFetch<Alert[]>(api.getAllAlerts);

  const handleAcknowledge = async (alertId: string) => {
    try {
      await api.acknowledgeAlert(alertId);
      refetch();
    } catch (e) {
      console.error('Failed to acknowledge alert:', e);
    }
  };

  if (loading) {
    return (
      <div className="page-enter" style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
        <div className="loading-spinner" />
      </div>
    );
  }

  return (
    <div className="page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-lg)' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Active Alerts</h2>
        <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          {alerts?.length ?? 0} unacknowledged
        </span>
      </div>

      {alerts && alerts.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-md)' }}>
          {alerts.map((alert) => (
            <div key={alert.id} className="card" style={{
              borderLeftWidth: '3px',
              borderLeftColor: `var(--severity-${severityClass(alert.severity)})`,
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                    <span className={`severity-badge ${severityClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', fontWeight: 600 }}>
                      {alert.cveId}
                    </span>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {timeAgo(alert.createdAt)}
                    </span>
                  </div>

                  <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    {truncate(alert.message, 200)}
                  </div>

                  <div style={{ display: 'flex', gap: '16px', fontSize: '13px', color: 'var(--text-muted)' }}>
                    <span>📦 {alert.packageName}</span>
                    <span>📊 Score: {formatScore(alert.riskScore)}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                  <div className={`risk-score ${severityClass(alert.severity)}`}>
                    {formatScore(alert.riskScore)}
                  </div>
                  <button
                    className="btn btn-sm"
                    onClick={() => handleAcknowledge(alert.id)}
                  >
                    ✓ Ack
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">✅</div>
            <div className="empty-state-text">All clear! No unacknowledged alerts.</div>
          </div>
        </div>
      )}
    </div>
  );
}
