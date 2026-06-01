import { useWebSocket } from '../../hooks/useData';

export default function Header() {
  const { isConnected } = useWebSocket();

  return (
    <header className="app-header">
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <h1 style={{ fontSize: '16px', fontWeight: 600, letterSpacing: '-0.01em' }}>
          Supply Chain Risk Monitor
        </h1>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
          <span className={`status-dot ${isConnected ? 'online' : 'offline'}`} />
          {isConnected ? 'Live' : 'Offline'}
        </div>
      </div>
    </header>
  );
}
