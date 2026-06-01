import { useRef, useEffect, useState, useCallback } from 'react';
import * as d3 from 'd3';
import type { GraphNode, GraphEdge } from '../../services/api';

/**
 * D3 simulation node with position/velocity fields.
 */
interface SimNode extends d3.SimulationNodeDatum, GraphNode {
  x: number;
  y: number;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  source: SimNode;
  target: SimNode;
}

interface DependencyGraphViewProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  width?: number;
  height?: number;
  onNodeClick?: (node: GraphNode) => void;
  searchTerm?: string;
  showLabels?: boolean;
  highlightVulnerable?: boolean;
}

/**
 * Interactive force-directed dependency graph using D3.js.
 *
 * Features:
 * - Force simulation with collision, charge, link, and center forces
 * - SVG rendering with zoom/pan (d3.zoom)
 * - Node coloring: red (vulnerable), cyan (direct), slate (transitive)
 * - Edge rendering with directional arrows
 * - Hover tooltips with vulnerability info
 * - Node search highlighting
 * - Drag interaction
 */
export default function DependencyGraphView({
  nodes,
  edges,
  width = 900,
  height = 600,
  onNodeClick,
  searchTerm = '',
  showLabels = true,
  highlightVulnerable = true,
}: DependencyGraphViewProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const getNodeColor = useCallback((node: GraphNode): string => {
    if (highlightVulnerable && node.vulnerable) return '#ef4444';
    if (node.direct) return '#06b6d4';
    return '#64748b';
  }, [highlightVulnerable]);

  const getNodeRadius = useCallback((node: GraphNode): number => {
    if (node.vulnerable) return 10;
    if (node.direct) return 8;
    return 5;
  }, []);

  const isHighlighted = useCallback((node: GraphNode): boolean => {
    if (!searchTerm) return false;
    return node.packageName.toLowerCase().includes(searchTerm.toLowerCase())
      || node.id.toLowerCase().includes(searchTerm.toLowerCase());
  }, [searchTerm]);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Clone nodes/edges for D3 mutation
    const simNodes: SimNode[] = nodes.map((n) => ({ ...n, x: 0, y: 0 }));
    const simLinks: SimLink[] = edges
      .map((e) => {
        const source = simNodes.find((n) => n.id === e.source);
        const target = simNodes.find((n) => n.id === e.target);
        if (!source || !target) return null;
        return { source, target } as SimLink;
      })
      .filter((l): l is SimLink => l !== null);

    // --- Defs (arrows, glow) ---
    const defs = svg.append('defs');

    // Arrow marker
    defs.append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', 'rgba(148, 163, 184, 0.4)');

    // Glow filter for vulnerable nodes
    const glowFilter = defs.append('filter')
      .attr('id', 'glow-red')
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%');
    glowFilter.append('feGaussianBlur')
      .attr('stdDeviation', '3')
      .attr('result', 'blur');
    glowFilter.append('feFlood')
      .attr('flood-color', '#ef4444')
      .attr('flood-opacity', '0.4')
      .attr('result', 'color');
    glowFilter.append('feComposite')
      .attr('in', 'color').attr('in2', 'blur')
      .attr('operator', 'in').attr('result', 'glow');
    const glowMerge = glowFilter.append('feMerge');
    glowMerge.append('feMergeNode').attr('in', 'glow');
    glowMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Search highlight glow
    const searchGlow = defs.append('filter')
      .attr('id', 'glow-search')
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%');
    searchGlow.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'blur');
    searchGlow.append('feFlood')
      .attr('flood-color', '#eab308')
      .attr('flood-opacity', '0.6')
      .attr('result', 'color');
    searchGlow.append('feComposite')
      .attr('in', 'color').attr('in2', 'blur')
      .attr('operator', 'in').attr('result', 'glow');
    const searchMerge = searchGlow.append('feMerge');
    searchMerge.append('feMergeNode').attr('in', 'glow');
    searchMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // --- Container group (for zoom/pan) ---
    const container = svg.append('g').attr('class', 'graph-container');

    // --- Zoom behavior ---
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        container.attr('transform', event.transform);
      });
    svg.call(zoom);

    // Center initial view
    svg.call(zoom.transform, d3.zoomIdentity.translate(width / 2, height / 2));

    // --- Links ---
    const linkGroup = container.append('g').attr('class', 'links');
    const link = linkGroup.selectAll('line')
      .data(simLinks)
      .join('line')
      .attr('stroke', 'rgba(148, 163, 184, 0.15)')
      .attr('stroke-width', 1)
      .attr('marker-end', 'url(#arrowhead)');

    // --- Node groups ---
    const nodeGroup = container.append('g').attr('class', 'nodes');
    const node = nodeGroup.selectAll<SVGGElement, SimNode>('g')
      .data(simNodes)
      .join('g')
      .attr('class', 'node-group')
      .style('cursor', 'pointer');

    // Node circles
    node.append('circle')
      .attr('r', (d) => getNodeRadius(d))
      .attr('fill', (d) => getNodeColor(d))
      .attr('stroke', (d) => {
        if (isHighlighted(d)) return '#eab308';
        if (d.vulnerable) return '#ef4444';
        return 'rgba(148, 163, 184, 0.3)';
      })
      .attr('stroke-width', (d) => isHighlighted(d) ? 3 : 1.5)
      .attr('filter', (d) => {
        if (isHighlighted(d)) return 'url(#glow-search)';
        if (d.vulnerable) return 'url(#glow-red)';
        return 'none';
      })
      .style('transition', 'all 0.2s ease');

    // Node labels
    if (showLabels) {
      node.append('text')
        .text((d) => {
          const name = d.packageName;
          return name.length > 20 ? name.slice(0, 18) + '…' : name;
        })
        .attr('dx', (d) => getNodeRadius(d) + 4)
        .attr('dy', 4)
        .attr('font-size', '10px')
        .attr('fill', (d) => isHighlighted(d) ? '#eab308' : 'rgba(241, 245, 249, 0.6)')
        .attr('font-family', 'Inter, sans-serif')
        .attr('font-weight', (d) => d.vulnerable || isHighlighted(d) ? '600' : '400')
        .attr('pointer-events', 'none');
    }

    // --- Tooltip ---
    const tooltip = d3.select(tooltipRef.current);

    node.on('mouseenter', (event, d) => {
      // Highlight connected edges
      link.attr('stroke', (l) =>
        l.source.id === d.id || l.target.id === d.id
          ? 'rgba(6, 182, 212, 0.6)'
          : 'rgba(148, 163, 184, 0.08)'
      ).attr('stroke-width', (l) =>
        l.source.id === d.id || l.target.id === d.id ? 2 : 0.5
      );

      // Show tooltip
      tooltip
        .style('display', 'block')
        .style('left', `${event.pageX + 12}px`)
        .style('top', `${event.pageY - 10}px`)
        .html(`
          <div style="font-weight: 600; margin-bottom: 4px; color: ${getNodeColor(d)}">
            ${d.packageName}
          </div>
          <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px">
            v${d.version} · ${d.ecosystem}
          </div>
          <div style="font-size: 11px">
            ${d.direct ? '📌 Direct dependency' : '🔗 Transitive dependency'}
          </div>
          ${d.vulnerable ? `
            <div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(148,163,184,0.2)">
              <div style="color: #ef4444; font-weight: 600; font-size: 11px">
                ⚠️ ${d.vulnerabilities.length} vulnerabilit${d.vulnerabilities.length === 1 ? 'y' : 'ies'}
              </div>
              <div style="font-size: 10px; color: #94a3b8; margin-top: 2px; font-family: 'JetBrains Mono', monospace">
                ${d.vulnerabilities.slice(0, 3).join(', ')}${d.vulnerabilities.length > 3 ? ` +${d.vulnerabilities.length - 3} more` : ''}
              </div>
            </div>
          ` : ''}
        `);
    });

    node.on('mouseleave', () => {
      link.attr('stroke', 'rgba(148, 163, 184, 0.15)').attr('stroke-width', 1);
      tooltip.style('display', 'none');
    });

    node.on('click', (_, d) => {
      setSelectedNode(d.id);
      onNodeClick?.(d);
    });

    // --- Drag behavior ---
    const drag = d3.drag<SVGGElement, SimNode>()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    node.call(drag);

    // --- Force simulation ---
    const simulation = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink<SimNode, SimLink>(simLinks)
        .id((d) => d.id)
        .distance(80)
        .strength(0.5))
      .force('charge', d3.forceManyBody()
        .strength((d) => (d as SimNode).vulnerable ? -200 : -120)
        .distanceMax(300))
      .force('collision', d3.forceCollide<SimNode>()
        .radius((d) => getNodeRadius(d) + 10))
      .force('center', d3.forceCenter(0, 0))
      .force('x', d3.forceX(0).strength(0.05))
      .force('y', d3.forceY(0).strength(0.05))
      .alphaDecay(0.02)
      .on('tick', () => {
        link
          .attr('x1', (d) => d.source.x)
          .attr('y1', (d) => d.source.y)
          .attr('x2', (d) => d.target.x)
          .attr('y2', (d) => d.target.y);

        node.attr('transform', (d) => `translate(${d.x},${d.y})`);
      });

    // Cleanup
    return () => {
      simulation.stop();
      tooltip.style('display', 'none');
    };
  }, [nodes, edges, width, height, searchTerm, showLabels, highlightVulnerable, getNodeColor, getNodeRadius, isHighlighted, onNodeClick]);

  return (
    <div style={{ position: 'relative' }}>
      <svg
        ref={svgRef}
        width={width}
        height={height}
        style={{
          background: 'var(--bg-primary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)',
        }}
      />

      {/* Tooltip */}
      <div
        ref={tooltipRef}
        style={{
          display: 'none',
          position: 'fixed',
          background: 'rgba(15, 23, 42, 0.95)',
          border: '1px solid rgba(148, 163, 184, 0.2)',
          borderRadius: '8px',
          padding: '10px 14px',
          fontSize: '12px',
          color: '#f1f5f9',
          backdropFilter: 'blur(8px)',
          zIndex: 1000,
          pointerEvents: 'none',
          maxWidth: '280px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)',
        }}
      />

      {/* Legend */}
      <div style={{
        position: 'absolute',
        bottom: '12px',
        left: '12px',
        display: 'flex',
        gap: '16px',
        padding: '8px 12px',
        background: 'rgba(15, 23, 42, 0.85)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-subtle)',
        fontSize: '11px',
        color: 'var(--text-secondary)',
        backdropFilter: 'blur(8px)',
      }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#06b6d4', display: 'inline-block' }} />
          Direct
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#64748b', display: 'inline-block' }} />
          Transitive
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444', display: 'inline-block', boxShadow: '0 0 6px #ef4444' }} />
          Vulnerable
        </span>
        {searchTerm && (
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#eab308', display: 'inline-block', boxShadow: '0 0 6px #eab308' }} />
            Search match
          </span>
        )}
      </div>

      {/* Node count */}
      <div style={{
        position: 'absolute',
        top: '12px',
        right: '12px',
        padding: '6px 10px',
        background: 'rgba(15, 23, 42, 0.85)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-subtle)',
        fontSize: '11px',
        color: 'var(--text-muted)',
        backdropFilter: 'blur(8px)',
      }}>
        {nodes.length} nodes · {edges.length} edges
        {selectedNode && (
          <span style={{ marginLeft: '8px', color: 'var(--accent-cyan)' }}>
            Selected: {selectedNode.split(':')[0]}
          </span>
        )}
      </div>
    </div>
  );
}
