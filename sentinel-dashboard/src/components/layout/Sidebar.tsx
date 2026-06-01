import { NavLink } from 'react-router-dom';

export default function Sidebar() {
  return (
    <aside className="app-sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">S</div>
        <span className="sidebar-logo-text">SENTINEL</span>
      </div>

      <div className="sidebar-section-label">Monitor</div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`} end>
          <span className="sidebar-link-icon">📊</span>
          Overview
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
          <span className="sidebar-link-icon">🔔</span>
          Alerts
        </NavLink>
        <NavLink to="/vulnerabilities" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
          <span className="sidebar-link-icon">🛡️</span>
          Vulnerabilities
        </NavLink>
      </nav>

      <div className="sidebar-section-label">Explore</div>
      <nav className="sidebar-nav">
        <NavLink to="/graph" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
          <span className="sidebar-link-icon">🕸️</span>
          Dependency Graph
        </NavLink>
        <NavLink to="/timeline" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
          <span className="sidebar-link-icon">📅</span>
          Event Timeline
        </NavLink>
      </nav>
    </aside>
  );
}
