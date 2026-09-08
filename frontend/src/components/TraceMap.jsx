import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import { MapPin, Globe, ShieldAlert, Cpu, Radio } from 'lucide-react';

export default function TraceMap({ email }) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const markerGroupRef = useRef(null);

  const origin = email?.origin || {
    ip: '127.0.0.1',
    country: 'Unknown',
    city: 'Unknown',
    lat: 20.0,
    lng: 0.0,
    is_vpn_tor: false,
    isp: 'Unknown ISP',
    asn: 'N/A'
  };

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Initialize Map if not already created
    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [origin.lat, origin.lng],
        zoom: 4,
        zoomControl: false,
        attributionControl: false,
      });

      // CartoDB Dark Matter Tiles (High-contrast SOC Cyberpunk look)
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        subdomains: 'abcd',
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
      }).addTo(map);

      // Add custom zoom control in top-right
      L.control.zoom({ position: 'topright' }).addTo(map);

      // Add layer group for markers
      const markerGroup = L.layerGroup().addTo(map);
      markerGroupRef.current = markerGroup;
      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;
    const markerGroup = markerGroupRef.current;

    // Trigger invalidateSize to ensure tiles render immediately across full container
    setTimeout(() => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.invalidateSize();
      }
    }, 150);

    // Clear previous markers
    if (markerGroup) {
      markerGroup.clearLayers();
    }

    // Smooth fly to new coordinates
    map.flyTo([origin.lat, origin.lng], 5, {
      duration: 1.5,
      easeLinearity: 0.25
    });

    // Create Cyber Radar Pulsing DivIcon
    const isMalicious = email?.fraud_score > 70;
    const pulseColor = isMalicious ? '#ef4444' : email?.fraud_score > 40 ? '#f59e0b' : '#10b981';
    const bgGlow = isMalicious ? 'rgba(239, 68, 68, 0.4)' : email?.fraud_score > 40 ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)';

    const customIcon = L.divIcon({
      className: 'custom-radar-marker',
      html: `
        <div style="position: relative; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;">
          <div style="position: absolute; width: 32px; height: 32px; border-radius: 50%; background: ${bgGlow}; border: 1.5px solid ${pulseColor}; animation: pulse-ring 2s infinite;"></div>
          <div style="width: 12px; height: 12px; border-radius: 50%; background: ${pulseColor}; box-shadow: 0 0 10px ${pulseColor};"></div>
        </div>
      `,
      iconSize: [32, 32],
      iconAnchor: [16, 16],
    });

    // Add Marker with Rich Forensic Popup
    const marker = L.marker([origin.lat, origin.lng], { icon: customIcon }).addTo(markerGroup);

    const popupContent = `
      <div style="font-family: 'JetBrains Mono', monospace; min-width: 220px; font-size: 11px;">
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 6px; margin-bottom: 6px;">
          <span style="color: #38bdf8; font-weight: bold;">ORIGIN GEO-TRACE</span>
          <span style="padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold; background: ${isMalicious ? '#7f1d1d' : '#064e3b'}; color: ${isMalicious ? '#fca5a5' : '#6ee7b7'};">
            ${email?.verdict || 'MALICIOUS'}
          </span>
        </div>
        <div style="margin-bottom: 4px;"><strong style="color: #94a3b8;">IP:</strong> <span style="color: #f1f5f9;">${origin.ip}</span></div>
        <div style="margin-bottom: 4px;"><strong style="color: #94a3b8;">Location:</strong> <span style="color: #f1f5f9;">${origin.city}, ${origin.country}</span></div>
        <div style="margin-bottom: 4px;"><strong style="color: #94a3b8;">Coordinates:</strong> <span style="color: #38bdf8;">${origin.lat.toFixed(4)}, ${origin.lng.toFixed(4)}</span></div>
        <div style="margin-bottom: 4px;"><strong style="color: #94a3b8;">Network:</strong> <span style="color: #cbd5e1;">${origin.isp || 'N/A'}</span></div>
        <div style="margin-top: 6px; padding-top: 4px; border-top: 1px dashed #334155; display: flex; align-items: center; justify-content: space-between;">
          <span style="color: #94a3b8;">TOR/VPN Exit:</span>
          <span style="color: ${origin.is_vpn_tor ? '#f87171' : '#4ade80'}; font-weight: bold;">${origin.is_vpn_tor ? 'YES (MASKED)' : 'NO (DIRECT)'}</span>
        </div>
      </div>
    `;

    marker.bindPopup(popupContent).openPopup();
  }, [email]);

  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  return (
    <div className="bg-slate-900/90 rounded-lg border border-slate-800 p-3 flex flex-col h-[280px] shadow-lg relative overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs font-mono">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Globe className="w-4 h-4 animate-spin" style={{ animationDuration: '12s' }} />
          <span className="font-semibold tracking-wider">GEOSPATIAL ORIGIN TRACE</span>
        </div>
        <div className="flex items-center space-x-2">
          {origin.is_vpn_tor && (
            <span className="px-2 py-0.5 rounded text-[10px] bg-red-950/80 text-red-400 border border-red-800/80 flex items-center gap-1 font-bold animate-pulse">
              <ShieldAlert className="w-3 h-3" /> TOR / PROXY DETECTED
            </span>
          )}
          <span className="text-slate-400 text-[11px]">
            {origin.city}, {origin.country}
          </span>
        </div>
      </div>

      {/* Map Container */}
      <div className="flex-1 rounded border border-slate-800/80 overflow-hidden relative">
        <div ref={mapContainerRef} className="w-full h-full" />
        
        {/* Radar HUD overlay corners */}
        <div className="absolute top-2 left-2 z-20 pointer-events-none bg-slate-950/80 backdrop-blur-sm border border-slate-700/60 px-2 py-1 rounded text-[10px] font-mono text-slate-300 flex items-center gap-1.5 shadow-md">
          <Radio className="w-3 h-3 text-cyan-400 animate-ping" />
          <span>IP: <strong className="text-cyan-300">{origin.ip}</strong></span>
        </div>

        <div className="absolute bottom-2 right-2 z-20 pointer-events-none bg-slate-950/80 backdrop-blur-sm border border-slate-700/60 px-2 py-0.5 rounded text-[9px] font-mono text-slate-400 shadow-md">
          ASN: {origin.asn || 'AS-UNKNOWN'} | {origin.lat.toFixed(2)}°N, {origin.lng.toFixed(2)}°E
        </div>
      </div>
    </div>
  );
}
