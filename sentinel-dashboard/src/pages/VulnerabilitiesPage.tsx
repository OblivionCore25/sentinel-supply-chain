import { api, type Vulnerability } from '../services/api';
import { useFetch } from '../hooks/useData';
import { severityClass, formatScore, timeAgo, truncate } from '../utils/helpers';

export default function VulnerabilitiesPage() {
  const { data: vulnerabilities, loading } = useFetch<Vulnerability[]>(api.getVulnerabilities);

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
        <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Vulnerabilities</h2>
        <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          {vulnerabilities?.length ?? 0} tracked
        </span>
      </div>

      {vulnerabilities && vulnerabilities.length > 0 ? (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Package</th>
                <th>CVSS</th>
                <th>Severity</th>
                <th>Affected Range</th>
                <th>Source</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.map((vuln) => (
                <tr key={vuln.id}>
                  <td>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600 }}
                    >
                      {vuln.cveId}
                    </a>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
                    {truncate(vuln.packageName, 35)}
                  </td>
                  <td>
                    <span style={{
                      fontWeight: 700,
                      color: `var(--severity-${severityClass(vuln.severity)})`,
                      fontVariantNumeric: 'tabular-nums'
                    }}>
                      {formatScore(vuln.cvssScore)}
                    </span>
                  </td>
                  <td>
                    <span className={`severity-badge ${severityClass(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {vuln.affectedRange || '—'}
                  </td>
                  <td>
                    <span style={{
                      fontSize: '12px', padding: '2px 8px',
                      borderRadius: 'var(--radius-full)',
                      background: 'var(--accent-cyan-dim)',
                      color: 'var(--accent-cyan)',
                    }}>
                      {vuln.source}
                    </span>
                  </td>
                  <td style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                    {vuln.publishedAt ? timeAgo(vuln.publishedAt) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-text">No vulnerabilities tracked yet. They will appear after ingestion.</div>
          </div>
        </div>
      )}
    </div>
  );
}
