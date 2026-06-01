// Graph controls for search, filters, and stats

interface GraphControlsProps {
  searchTerm: string;
  onSearchChange: (term: string) => void;
  showLabels: boolean;
  onToggleLabels: () => void;
  highlightVulnerable: boolean;
  onToggleVulnerable: () => void;
  nodeCount: number;
  edgeCount: number;
  vulnerableCount: number;
  directCount: number;
}

/**
 * Control panel for the dependency graph visualization.
 * Provides search, filters, and graph statistics.
 */
export default function GraphControls({
  searchTerm,
  onSearchChange,
  showLabels,
  onToggleLabels,
  highlightVulnerable,
  onToggleVulnerable,
  nodeCount,
  edgeCount,
  vulnerableCount,
  directCount,
}: GraphControlsProps) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 'var(--space-md)',
      padding: 'var(--space-md)',
      background: 'var(--bg-card)',
      border: '1px solid var(--border-subtle)',
      borderRadius: 'var(--radius-lg)',
      marginBottom: 'var(--space-md)',
      flexWrap: 'wrap',
    }}>
      {/* Search */}
      <div style={{ flex: '1 1 220px', position: 'relative' }}>
        <span style={{
          position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)',
          fontSize: '14px', color: 'var(--text-muted)', pointerEvents: 'none',
        }}>
          🔍
        </span>
        <input
          type="text"
          placeholder="Search packages…"
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          style={{
            width: '100%',
            padding: '8px 12px 8px 34px',
            background: 'var(--bg-input)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--text-primary)',
            fontSize: '13px',
            outline: 'none',
            transition: 'border-color var(--transition-fast)',
          }}
          onFocus={(e) => e.target.style.borderColor = 'var(--accent-cyan)'}
          onBlur={(e) => e.target.style.borderColor = 'var(--border-default)'}
        />
      </div>

      {/* Toggle buttons */}
      <button
        className={`btn btn-sm ${showLabels ? 'btn-primary' : ''}`}
        onClick={onToggleLabels}
        title="Toggle package name labels"
      >
        🏷️ Labels
      </button>

      <button
        className={`btn btn-sm ${highlightVulnerable ? 'btn-primary' : ''}`}
        onClick={onToggleVulnerable}
        title="Highlight vulnerable nodes"
      >
        ⚠️ Vulnerabilities
      </button>

      {/* Stats */}
      <div style={{
        display: 'flex',
        gap: 'var(--space-md)',
        fontSize: '12px',
        color: 'var(--text-muted)',
        marginLeft: 'auto',
      }}>
        <span title="Total packages">📦 {nodeCount}</span>
        <span title="Dependencies">🔗 {edgeCount}</span>
        <span title="Direct dependencies" style={{ color: 'var(--accent-cyan)' }}>
          📌 {directCount}
        </span>
        <span title="Vulnerable packages" style={{ color: vulnerableCount > 0 ? 'var(--severity-critical)' : 'var(--text-muted)' }}>
          🔴 {vulnerableCount}
        </span>
      </div>
    </div>
  );
}
