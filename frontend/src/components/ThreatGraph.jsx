import React, { useEffect, useRef, useState } from 'react';
import { Network } from 'vis-network/standalone';
import { Network as NetworkIcon, RefreshCw, ZoomIn, ZoomOut, Info, ShieldAlert } from 'lucide-react';

export default function ThreatGraph({ email }) {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!containerRef.current || !email) return;

    // Build Graph Nodes
    const nodes = [
      {
        id: 'email_target',
        label: `Target Email\n${email.id}`,
        shape: 'box',
        color: {
          background: '#1e3a8a',
          border: '#3b82f6',
          highlight: { background: '#2563eb', border: '#60a5fa' }
        },
        font: { color: '#ffffff', face: 'JetBrains Mono', size: 12 },
        margin: 10,
        type: 'Email Entity',
        details: `Subject: ${email.subject}\nRecipient: ${email.recipient || 'treasury.ops@targetdefense.org'}`
      },
      {
        id: 'sender_domain',
        label: `Domain\n${email.domain || email.sender.split('@')[1] || 'unknown-domain.com'}`,
        shape: 'hexagon',
        color: {
          background: '#7c2d12',
          border: '#f97316',
          highlight: { background: '#c2410c', border: '#fb923c' }
        },
        font: { color: '#ffffff', face: 'JetBrains Mono', size: 11 },
        margin: 8,
        type: 'Sender Domain',
        details: `Domain: ${email.domain || email.sender.split('@')[1]}\nSpoofed: ${email.fraud_score > 70 ? 'Yes' : 'No'}`
      },
      {
        id: 'origin_ip',
        label: `Origin IP\n${email.origin.ip}`,
        shape: 'dot',
        size: 22,
        color: {
          background: '#991b1b',
          border: '#ef4444',
          highlight: { background: '#dc2626', border: '#f87171' }
        },
        font: { color: '#ffffff', face: 'JetBrains Mono', size: 11 },
        type: 'Origin IP',
        details: `IP: ${email.origin.ip}\nGeo: ${email.origin.city}, ${email.origin.country}\nTOR/VPN: ${email.origin.is_vpn_tor ? 'TRUE' : 'FALSE'}`
      },
      {
        id: 'threat_actor',
        label: `Threat Actor\n${email.threat_group_id || 'UNKNOWN'}`,
        shape: 'diamond',
        size: 24,
        color: {
          background: '#581c87',
          border: '#a855f7',
          highlight: { background: '#7e22ce', border: '#c084fc' }
        },
        font: { color: '#ffffff', face: 'JetBrains Mono', size: 11 },
        type: 'Threat Attribution',
        details: `Actor ID: ${email.threat_group_id}\nSeverity: ${email.fraud_score >= 70 ? 'HIGH / CRITICAL' : 'ELEVATED'}`
      }
    ];

    // Add IOC URLs and C2 nodes if present
    if (email.iocs?.urls && email.iocs.urls.length > 0) {
      email.iocs.urls.slice(0, 2).forEach((url, idx) => {
        const shortUrl = url.replace(/https?:\/\//, '').split('/')[0];
        nodes.push({
          id: `ioc_url_${idx}`,
          label: `Malicious URL\n${shortUrl}`,
          shape: 'triangle',
          size: 16,
          color: {
            background: '#831843',
            border: '#f43f5e',
            highlight: { background: '#be123c', border: '#fb7185' }
          },
          font: { color: '#ffffff', face: 'JetBrains Mono', size: 10 },
          type: 'C2 / Phishing URL',
          details: `URL: ${url}`
        });
      });
    }

    if (email.iocs?.c2_ips && email.iocs.c2_ips.length > 0) {
      email.iocs.c2_ips.forEach((c2Ip, idx) => {
        if (c2Ip !== email.origin.ip) {
          nodes.push({
            id: `c2_node_${idx}`,
            label: `C2 Beacon\n${c2Ip}`,
            shape: 'square',
            size: 16,
            color: {
              background: '#450a0a',
              border: '#ef4444',
              highlight: { background: '#b91c1c', border: '#fca5a5' }
            },
            font: { color: '#ffffff', face: 'JetBrains Mono', size: 10 },
            type: 'Command & Control Relay',
            details: `C2 IP: ${c2Ip}\nActive Beaconing: Detected`
          });
        }
      });
    }

    // Build Graph Edges
    const edges = [
      { from: 'sender_domain', to: 'email_target', label: 'transmits', color: { color: '#38bdf8' }, arrows: 'to', font: { color: '#94a3b8', size: 9, face: 'JetBrains Mono' } },
      { from: 'origin_ip', to: 'sender_domain', label: 'relayed_by', color: { color: '#f97316' }, arrows: 'to', font: { color: '#94a3b8', size: 9, face: 'JetBrains Mono' } },
      { from: 'threat_actor', to: 'origin_ip', label: 'infrastructure_of', color: { color: '#a855f7' }, arrows: 'to', dashes: true, font: { color: '#94a3b8', size: 9, face: 'JetBrains Mono' } }
    ];

    if (email.iocs?.urls && email.iocs.urls.length > 0) {
      email.iocs.urls.slice(0, 2).forEach((_, idx) => {
        edges.push({
          from: 'email_target',
          to: `ioc_url_${idx}`,
          label: 'contains_link',
          color: { color: '#f43f5e' },
          arrows: 'to',
          font: { color: '#94a3b8', size: 9, face: 'JetBrains Mono' }
        });
      });
    }

    if (email.iocs?.c2_ips && email.iocs.c2_ips.length > 0) {
      email.iocs.c2_ips.forEach((c2Ip, idx) => {
        if (c2Ip !== email.origin.ip) {
          edges.push({
            from: 'origin_ip',
            to: `c2_node_${idx}`,
            label: 'C2_tunnel',
            color: { color: '#ef4444' },
            arrows: 'to',
            font: { color: '#94a3b8', size: 9, face: 'JetBrains Mono' }
          });
        }
      });
    }

    const data = { nodes, edges };

    const options = {
      nodes: {
        borderWidth: 2,
        shadow: {
          enabled: true,
          color: 'rgba(0,0,0,0.6)',
          size: 6
        }
      },
      edges: {
        width: 1.5,
        smooth: {
          type: 'continuous',
          roundness: 0.3
        }
      },
      physics: {
        stabilization: true,
        barnesHut: {
          gravitationalConstant: -2800,
          springConstant: 0.04,
          springLength: 95
        }
      },
      interaction: {
        hover: true,
        zoomView: true,
        dragView: true
      }
    };

    const network = new Network(containerRef.current, data, options);
    networkRef.current = network;

    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const nodeObj = nodes.find(n => n.id === nodeId);
        setSelectedNode(nodeObj || null);
      } else {
        setSelectedNode(null);
      }
    });

    return () => {
      network.destroy();
    };
  }, [email]);

  const handleResetView = () => {
    if (networkRef.current) {
      networkRef.current.fit({
        animation: { duration: 800, easingFunction: 'easeInOutQuad' }
      });
    }
  };

  const handleZoom = (direction) => {
    if (networkRef.current) {
      const scale = networkRef.current.getScale();
      networkRef.current.moveTo({
        scale: direction === 'in' ? scale * 1.3 : scale * 0.7,
        animation: { duration: 300 }
      });
    }
  };

  return (
    <div className="bg-slate-900/90 rounded-lg border border-slate-800 p-3 flex flex-col h-[320px] shadow-lg relative overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs font-mono">
        <div className="flex items-center space-x-2 text-cyan-400">
          <NetworkIcon className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold tracking-wider">THREAT INFRASTRUCTURE GRAPH</span>
        </div>
        <div className="flex items-center space-x-1">
          <button
            onClick={() => handleZoom('in')}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => handleZoom('out')}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetView}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Recenter Graph"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Legend tags */}
      <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400 mb-1.5 px-1">
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-sm bg-blue-600 border border-blue-400"></span>
          <span>Target Email</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-sm bg-orange-600 border border-orange-400"></span>
          <span>Domain</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-red-600 border border-red-400"></span>
          <span>Origin IP</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-sm bg-purple-600 border border-purple-400"></span>
          <span>Actor</span>
        </div>
      </div>

      {/* Canvas container */}
      <div className="flex-1 rounded border border-slate-800/80 bg-slate-950/60 relative overflow-hidden">
        <div ref={containerRef} className="w-full h-full" />

        {/* Selected Node Overlay */}
        {selectedNode && (
          <div className="absolute bottom-2 left-2 right-2 bg-slate-900/95 border border-cyan-500/50 rounded p-2 text-xs font-mono backdrop-blur-md shadow-2xl animate-in fade-in slide-in-from-bottom-2 duration-200">
            <div className="flex items-center justify-between border-b border-slate-700 pb-1 mb-1">
              <span className="text-cyan-400 font-bold flex items-center gap-1">
                <Info className="w-3.5 h-3.5" /> {selectedNode.type}
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-200 text-[10px]"
              >
                ✕
              </button>
            </div>
            <pre className="text-[11px] text-slate-300 whitespace-pre-wrap leading-tight">
              {selectedNode.details}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
