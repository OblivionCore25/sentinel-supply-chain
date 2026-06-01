import { useState, useRef, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api, type GraphData, type GraphNode, type Project } from '../services/api';
import { useFetch } from '../hooks/useData';
import DependencyGraphView from '../components/graph/DependencyGraphView';
import GraphControls from '../components/graph/GraphControls';

export default function GraphPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const projectId = searchParams.get('project');

  const { data: projects } = useFetch<Project[]>(api.getProjects);
  const { data: graphData, loading } = useFetch<GraphData | null>(
    () => projectId ? api.getProjectGraph(projectId) : Promise.resolve(null),
    [projectId]
  );

  // Graph controls state
  const [searchTerm, setSearchTerm] = useState('');
  const [showLabels, setShowLabels] = useState(true);
  const [highlightVulnerable, setHighlightVulnerable] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Container ref for dynamic sizing
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 900, height: 600 });

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setDimensions({
          width: Math.max(rect.width - 2, 600),  // -2 for border
          height: Math.max(window.innerHeight - 280, 400),
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  const handleProjectChange = (newProjectId: string) => {
    if (newProjectId) {
      setSearchParams({ project: newProjectId });
    } else {
      setSearchParams({});
    }
    setSelectedNode(null);
    setSearchTerm('');
  };

  return (
    <div className="page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-lg)' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Dependency Graph</h2>

        {/* Project selector */}
        <select
          value={projectId ?? ''}
          onChange={(e) => handleProjectChange(e.target.value)}
          style={{
            background: 'var(--bg-input)', border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)', padding: '8px 12px', fontSize: '14px',
            color: 'var(--text-primary)', cursor: 'pointer', minWidth: '200px',
          }}
        >
          <option value="">Select a project…</option>
          {projects?.map((p) => (
            <option key={p.id} value={p.id}>{p.name} ({p.ecosystem})</option>
          ))}
        </select>
      </div>

      {!projectId ? (
        <div className="card" style={{ minHeight: '500px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <div className="empty-state-icon">🕸️</div>
            <div className="empty-state-text">Select a project to visualize its dependency graph.</div>
          </div>
        </div>
      ) : loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '120px 0' }}>
          <div className="loading-spinner" />
        </div>
      ) : graphData && graphData.nodes.length > 0 ? (
        <div ref={containerRef}>
          {/* Controls */}
          <GraphControls
            searchTerm={searchTerm}
            onSearchChange={setSearchTerm}
            showLabels={showLabels}
            onToggleLabels={() => setShowLabels(!showLabels)}
            highlightVulnerable={highlightVulnerable}
            onToggleVulnerable={() => setHighlightVulnerable(!highlightVulnerable)}
            nodeCount={graphData.nodes.length}
            edgeCount={graphData.edges.length}
            vulnerableCount={graphData.nodes.filter(n => n.vulnerable).length}
            directCount={graphData.nodes.filter(n => n.direct).length}
          />

          {/* D3 Graph */}
          <DependencyGraphView
            nodes={graphData.nodes}
            edges={graphData.edges}
            width={dimensions.width}
            height={dimensions.height}
            searchTerm={searchTerm}
            showLabels={showLabels}
            highlightVulnerable={highlightVulnerable}
            onNodeClick={(node) => setSelectedNode(node)}
          />

          {/* Selected node detail panel */}
          {selectedNode && (
            <div className="card" style={{
              marginTop: 'var(--space-md)',
              borderLeft: `3px solid ${selectedNode.vulnerable ? 'var(--severity-critical)' : 'var(--accent-cyan)'}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 600, marginBottom: '4px' }}>
                    {selectedNode.packageName}
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', gap: '16px' }}>
                    <span>v{selectedNode.version}</span>
                    <span>{selectedNode.ecosystem}</span>
                    <span>{selectedNode.direct ? '📌 Direct' : '🔗 Transitive'}</span>
                  </div>
                  {selectedNode.vulnerable && (
                    <div style={{ marginTop: '8px' }}>
                      <span style={{ color: 'var(--severity-critical)', fontWeight: 600, fontSize: '13px' }}>
                        ⚠️ {selectedNode.vulnerabilities.length} known vulnerabilit{selectedNode.vulnerabilities.length === 1 ? 'y' : 'ies'}:
                      </span>
                      <div style={{
                        marginTop: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px',
                        display: 'flex', flexWrap: 'wrap', gap: '6px'
                      }}>
                        {selectedNode.vulnerabilities.map((cve) => (
                          <a
                            key={cve}
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              padding: '2px 8px', borderRadius: 'var(--radius-full)',
                              background: 'var(--severity-critical-bg)', color: 'var(--severity-critical)',
                            }}
                          >
                            {cve}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <button
                  className="btn btn-sm"
                  onClick={() => setSelectedNode(null)}
                >
                  ✕ Close
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="card" style={{ minHeight: '500px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="empty-state">
            <div className="empty-state-icon">📦</div>
            <div className="empty-state-text">No dependency data for this project. Submit a dependency snapshot via the API first.</div>
          </div>
        </div>
      )}
    </div>
  );
}
