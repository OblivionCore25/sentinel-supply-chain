import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';
import OverviewPage from './pages/OverviewPage';
import AlertsPage from './pages/AlertsPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import TimelinePage from './pages/TimelinePage';
import ProjectDetailPage from './pages/ProjectDetailPage';
import GraphPage from './pages/GraphPage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <Header />
        <main className="app-main">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/timeline" element={<TimelinePage />} />
            <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
            <Route path="/graph" element={<GraphPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
