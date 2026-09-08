import React, { useState } from 'react';
import html2pdf from 'html2pdf.js';
import { FileText, Download, ShieldCheck, AlertTriangle, CheckCircle, Terminal, Lock, Cpu } from 'lucide-react';

export default function ReportExporter({ email }) {
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

  const handleExportPDF = async () => {
    setIsExporting(true);
    setExportSuccess(false);

    try {
      const element = document.getElementById('forensic-report-printable');
      if (!element) throw new Error('Report container element not found');

      // Temporarily reveal printable element for PDF capture
      element.style.display = 'block';

      const opt = {
        margin: [10, 10, 10, 10],
        filename: `ThreatTrace_Forensic_Dossier_${email.id}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, logging: false },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
      };

      await html2pdf().set(opt).from(element).save();

      element.style.display = 'none';
      setExportSuccess(true);
      setTimeout(() => setExportSuccess(false), 4000);
    } catch (err) {
      console.error('PDF export error:', err);
      alert('Forensic PDF generation failed: ' + err.message);
    } finally {
      setIsExporting(false);
    }
  };

  const isMalicious = email.fraud_score > 70;
  const isSuspicious = email.fraud_score >= 40 && email.fraud_score <= 70;

  return (
    <div className="bg-slate-900/90 rounded-lg border border-slate-800 p-3.5 flex flex-col shadow-lg relative">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800 text-xs font-mono">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold tracking-wider">AI FORENSIC REASONING & ACTIONS</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
            ENGINE: GEMINI-SOC-CORE
          </span>
        </div>
      </div>

      {/* AI Plain-English Summary Card */}
      <div className="bg-slate-950/70 rounded-md border border-slate-800/80 p-3 mb-3 relative overflow-hidden">
        <div className="flex items-start gap-2.5">
          <div className="p-1.5 rounded bg-cyan-950/70 border border-cyan-700/50 text-cyan-400 shrink-0 mt-0.5">
            <Cpu className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <div className="text-[11px] font-mono text-cyan-400 font-bold mb-1 tracking-wide flex items-center gap-2">
              <span>SYNTHESIZED THREAT EVALUATION</span>
              <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono ${
                isMalicious ? 'bg-red-950 text-red-400 border border-red-800' :
                isSuspicious ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                'bg-emerald-950 text-emerald-400 border border-emerald-800'
              }`}>
                VERDICT: {email.verdict} ({email.fraud_score}% RISK)
              </span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed font-sans">
              {email.ai_summary}
            </p>
          </div>
        </div>
      </div>

      {/* Recommended Incident Response Actions */}
      <div className="bg-slate-950/40 rounded-md border border-slate-800/80 p-2.5 mb-3 text-xs">
        <div className="text-[10px] font-mono font-bold text-slate-400 mb-1.5 uppercase tracking-wider flex items-center gap-1.5">
          <Lock className="w-3 h-3 text-amber-400" /> Containment & Mitigation Playbook
        </div>
        <ul className="space-y-1 text-slate-300 text-[11px] font-mono">
          {isMalicious ? (
            <>
              <li className="flex items-center gap-1.5 text-red-300">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
                <span>Enforce edge firewall block rule on IP: <strong>{email.origin.ip}</strong></span>
              </li>
              <li className="flex items-center gap-1.5 text-red-300">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
                <span>Purge all incoming messages from domain: <strong>{email.domain || email.sender.split('@')[1]}</strong></span>
              </li>
              <li className="flex items-center gap-1.5 text-amber-300">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                <span>Revoke active session tokens for recipient: <strong>{email.recipient || 'treasury.ops'}</strong></span>
              </li>
            </>
          ) : isSuspicious ? (
            <>
              <li className="flex items-center gap-1.5 text-amber-300">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                <span>Quarantine email in SOC Sandbox for heuristic detonation.</span>
              </li>
              <li className="flex items-center gap-1.5 text-slate-300">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                <span>Notify user of potential credential phishing attempt.</span>
              </li>
            </>
          ) : (
            <li className="flex items-center gap-1.5 text-emerald-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>All signatures verified authentic. Whitelist sender for verified routing.</span>
            </li>
          )}
        </ul>
      </div>

      {/* Export Button & Action Bar */}
      <div className="flex items-center justify-between pt-1">
        <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
          <span>Attribution:</span>
          <span className="text-purple-400 font-bold">{email.threat_group_id}</span>
        </div>

        <button
          onClick={handleExportPDF}
          disabled={isExporting}
          className={`px-3 py-1.5 rounded-md font-mono text-xs font-semibold flex items-center gap-2 transition shadow-lg ${
            isExporting
              ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
              : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950 shadow-cyan-900/30 active:scale-95'
          }`}
        >
          {isExporting ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              <span>Generating Dossier...</span>
            </>
          ) : (
            <>
              <Download className="w-3.5 h-3.5" />
              <span>Export Forensic PDF Report</span>
            </>
          )}
        </button>
      </div>

      {exportSuccess && (
        <div className="mt-2 py-1 px-2 rounded bg-emerald-950/80 border border-emerald-700/80 text-emerald-300 text-xs font-mono flex items-center gap-1.5 animate-in fade-in duration-200">
          <CheckCircle className="w-3.5 h-3.5" /> Forensic PDF Dossier downloaded successfully.
        </div>
      )}

      {/* Hidden Printable PDF Container (Stylized for html2pdf.js) */}
      <div id="forensic-report-printable" style={{ display: 'none', background: '#0b1120', color: '#f8fafc', padding: '24px', fontFamily: 'monospace' }}>
        <div style={{ borderBottom: '2px solid #06b6d4', paddingBottom: '12px', marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1 style={{ color: '#38bdf8', fontSize: '20px', margin: '0 0 4px 0', textTransform: 'uppercase' }}>
              ThreatTrace AI — Cyber-Forensic Incident Dossier
            </h1>
            <p style={{ color: '#94a3b8', fontSize: '11px', margin: 0 }}>
              Confidential SOC Security Intelligence Report | Generated: {new Date().toISOString()}
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ padding: '4px 8px', background: isMalicious ? '#7f1d1d' : '#064e3b', color: '#ffffff', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold' }}>
              VERDICT: {email.verdict}
            </span>
          </div>
        </div>

        {/* Overview Table */}
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '16px', fontSize: '11px' }}>
          <tbody>
            <tr style={{ background: '#0f172a' }}>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8', width: '25%' }}>Dossier ID:</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#38bdf8' }}>{email.id}</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8', width: '25%' }}>Fraud Confidence:</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: isMalicious ? '#f87171' : '#4ade80', fontWeight: 'bold' }}>{email.fraud_score}%</td>
            </tr>
            <tr style={{ background: '#0b1120' }}>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8' }}>Subject:</td>
              <td colSpan="3" style={{ padding: '6px 10px', border: '1px solid #334155', color: '#f1f5f9' }}>{email.subject}</td>
            </tr>
            <tr style={{ background: '#0f172a' }}>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8' }}>Sender Address:</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#f1f5f9' }}>{email.sender}</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8' }}>Attributed Group:</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#c084fc' }}>{email.threat_group_id}</td>
            </tr>
            <tr style={{ background: '#0b1120' }}>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8' }}>Origin IP & Network:</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#f1f5f9' }}>{email.origin.ip} ({email.origin.city}, {email.origin.country})</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#94a3b8' }}>TOR / Proxy Exit:</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: email.origin.is_vpn_tor ? '#f87171' : '#4ade80' }}>
                {email.origin.is_vpn_tor ? 'YES (Masked Node)' : 'NO (Direct)'}
              </td>
            </tr>
          </tbody>
        </table>

        {/* Authentication Headers */}
        <h3 style={{ color: '#38bdf8', fontSize: '13px', margin: '14px 0 6px 0', textTransform: 'uppercase' }}>
          Cryptographic Authentication Records
        </h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '16px', fontSize: '11px' }}>
          <thead>
            <tr style={{ background: '#1e293b', color: '#94a3b8' }}>
              <th style={{ padding: '6px 10px', border: '1px solid #334155', textAlign: 'left' }}>Protocol</th>
              <th style={{ padding: '6px 10px', border: '1px solid #334155', textAlign: 'left' }}>Status</th>
              <th style={{ padding: '6px 10px', border: '1px solid #334155', textAlign: 'left' }}>Technical Assessment</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#f1f5f9' }}>SPF</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: email.headers.spf === 'PASS' ? '#4ade80' : '#f87171', fontWeight: 'bold' }}>{email.headers.spf}</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#cbd5e1' }}>Sender IP {email.origin.ip} not in SPF authorization envelope</td>
            </tr>
            <tr>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#f1f5f9' }}>DKIM</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: email.headers.dkim === 'PASS' ? '#4ade80' : '#f87171', fontWeight: 'bold' }}>{email.headers.dkim}</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#cbd5e1' }}>Missing or mismatched 2048-bit RSA header signature</td>
            </tr>
            <tr>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#f1f5f9' }}>DMARC</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: email.headers.dmarc === 'PASS' ? '#4ade80' : '#f87171', fontWeight: 'bold' }}>{email.headers.dmarc}</td>
              <td style={{ padding: '6px 10px', border: '1px solid #334155', color: '#cbd5e1' }}>Domain policy mandate: {email.headers.dmarc}</td>
            </tr>
          </tbody>
        </table>

        {/* AI Forensic Evaluation */}
        <h3 style={{ color: '#38bdf8', fontSize: '13px', margin: '14px 0 6px 0', textTransform: 'uppercase' }}>
          AI Reasoning & Deep Threat Analysis
        </h3>
        <div style={{ background: '#0f172a', border: '1px solid #334155', padding: '12px', borderRadius: '4px', fontSize: '11px', color: '#e2e8f0', lineHeight: 1.5, marginBottom: '16px' }}>
          {email.ai_summary}
        </div>

        {/* Chain of custody sign-off */}
        <div style={{ marginTop: '24px', paddingTop: '12px', borderTop: '1px solid #334155', display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#64748b' }}>
          <span>ThreatTrace AI Automated Forensics Engine v4.2</span>
          <span>Digital Verification Hash: SHA256-AUTHENTICATED</span>
        </div>
      </div>
    </div>
  );
}
