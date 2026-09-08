import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertOctagon, 
  Mail, 
  Clock, 
  User, 
  Send, 
  Code, 
  FileCheck, 
  ExternalLink, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronUp,
  Fingerprint
} from 'lucide-react';

export default function EmailDetail({ email }) {
  const [activeTab, setActiveTab] = useState('body'); // 'body', 'raw_headers', 'iocs'
  const [copied, setCopied] = useState(false);

  if (!email) {
    return (
      <div className="bg-slate-900/90 rounded-lg border border-slate-800 p-8 flex flex-col items-center justify-center text-slate-500 h-full font-mono">
        <Mail className="w-12 h-12 mb-3 text-slate-700 animate-pulse" />
        <p>SELECT AN EMAIL TO COMMENCE FORENSIC TRIAGE</p>
      </div>
    );
  }

  const isMalicious = email.fraud_score > 70;
  const isSuspicious = email.fraud_score >= 40 && email.fraud_score <= 70;
  const isBenign = email.fraud_score < 40;

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const headers = email.headers || { spf: 'UNKNOWN', dkim: 'UNKNOWN', dmarc: 'UNKNOWN' };

  return (
    <div className="bg-slate-900/90 rounded-lg border border-slate-800 p-4 flex flex-col shadow-lg space-y-4">
      {/* Top Banner: Verdict & Risk Score Meter */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {email.id}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/80">
              ACTOR: {email.threat_group_id || 'UNASSIGNED'}
            </span>
          </div>
          <h2 className="text-sm font-semibold text-slate-100 font-sans tracking-tight">
            {email.subject}
          </h2>
        </div>

        {/* Verdict Badge */}
        <div className="flex items-center gap-3">
          <div className="text-right font-mono">
            <div className="text-[10px] text-slate-400">FRAUD CONFIDENCE</div>
            <div className={`text-lg font-bold ${
              isMalicious ? 'text-red-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {email.fraud_score}%
            </div>
          </div>
          <div className={`px-3 py-1.5 rounded border text-xs font-mono font-bold flex items-center gap-1.5 shadow-sm ${
            isMalicious 
              ? 'bg-red-950/80 text-red-300 border-red-700 animate-pulse' 
              : isSuspicious 
              ? 'bg-amber-950/80 text-amber-300 border-amber-700' 
              : 'bg-emerald-950/80 text-emerald-300 border-emerald-700'
          }`}>
            {isMalicious ? <ShieldAlert className="w-4 h-4" /> : isSuspicious ? <AlertOctagon className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
            <span>{email.verdict}</span>
          </div>
        </div>
      </div>

      {/* Metadata Overview Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-slate-400">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-500">From:</span>
            <span className="text-slate-200 truncate font-semibold">{email.sender}</span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <Send className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-500">To:</span>
            <span className="text-slate-200 truncate">{email.recipient || 'corporate-inbox@targetdefense.org'}</span>
          </div>
        </div>
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-slate-400">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-500">Timestamp:</span>
            <span className="text-slate-200">{new Date(email.timestamp).toUTCString()}</span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-500">Return-Path:</span>
            <span className={`truncate ${headers.return_path && headers.return_path !== email.sender ? 'text-red-400 font-bold' : 'text-slate-300'}`}>
              {headers.return_path || email.sender}
            </span>
          </div>
        </div>
      </div>

      {/* Cryptographic Header Authentication Checks (SPF / DKIM / DMARC) */}
      <div>
        <div className="text-[11px] font-mono text-slate-400 font-semibold mb-1.5 uppercase tracking-wider flex items-center justify-between">
          <span>Cryptographic Header Verification</span>
          <span className="text-[10px] text-cyan-400">RFC 7208 / 6376 / 7489</span>
        </div>
        <div className="grid grid-cols-3 gap-2">
          {/* SPF Status */}
          <div className="bg-slate-950/80 border border-slate-800 p-2 rounded">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono text-slate-400 font-bold">SPF</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                headers.spf === 'PASS' 
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                  : 'bg-red-950 text-red-400 border border-red-800'
              }`}>
                {headers.spf}
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono line-clamp-1">
              {headers.spf === 'PASS' ? 'Authorized IP in SPF' : 'Envelope sender mismatch'}
            </p>
          </div>

          {/* DKIM Status */}
          <div className="bg-slate-950/80 border border-slate-800 p-2 rounded">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono text-slate-400 font-bold">DKIM</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                headers.dkim === 'PASS' 
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                  : 'bg-red-950 text-red-400 border border-red-800'
              }`}>
                {headers.dkim}
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono line-clamp-1">
              {headers.dkim === 'PASS' ? 'Valid RSA signature' : 'Signature missing/broken'}
            </p>
          </div>

          {/* DMARC Status */}
          <div className="bg-slate-950/80 border border-slate-800 p-2 rounded">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono text-slate-400 font-bold">DMARC</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                headers.dmarc === 'PASS' 
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                  : headers.dmarc === 'REJECT'
                  ? 'bg-red-950 text-red-400 border border-red-800'
                  : 'bg-amber-950 text-amber-400 border border-amber-800'
              }`}>
                {headers.dmarc}
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono line-clamp-1">
              {headers.dmarc === 'PASS' ? 'Aligned enforcement' : headers.dmarc === 'REJECT' ? 'Policy: p=reject' : 'Policy: p=none'}
            </p>
          </div>
        </div>
      </div>

      {/* Forensic Tabs: Body / Raw Headers / Extracted IOCs */}
      <div className="flex-1 flex flex-col min-h-[220px]">
        <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 mb-2 text-xs font-mono">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab('body')}
              className={`px-2.5 py-1 rounded transition ${
                activeTab === 'body'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sanitized Message View
            </button>
            <button
              onClick={() => setActiveTab('raw_headers')}
              className={`px-2.5 py-1 rounded transition ${
                activeTab === 'raw_headers'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Raw MIME Headers
            </button>
            <button
              onClick={() => setActiveTab('iocs')}
              className={`px-2.5 py-1 rounded transition flex items-center gap-1 ${
                activeTab === 'iocs'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>Extracted IOCs</span>
              {email.iocs?.urls?.length > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping"></span>
              )}
            </button>
          </div>

          <button
            onClick={() => copyToClipboard(activeTab === 'raw_headers' ? JSON.stringify(email.headers, null, 2) : email.full_body || email.body_preview)}
            className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[11px]"
            title="Copy content"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        {/* Tab Content Display */}
        <div className="flex-1 bg-slate-950/80 rounded border border-slate-800 p-3 overflow-y-auto max-h-[220px]">
          {activeTab === 'body' && (
            <div className="font-sans text-xs text-slate-200 whitespace-pre-wrap leading-relaxed space-y-2">
              <p className="font-mono text-[11px] text-slate-400 pb-2 border-b border-slate-800">
                [SANITIZED RENDERING ENGINE — JAVASCRIPT & TRACKERS STRIPPED]
              </p>
              <div>{email.full_body || email.body_preview}</div>
            </div>
          )}

          {activeTab === 'raw_headers' && (
            <pre className="font-mono text-[11px] text-cyan-300/90 whitespace-pre-wrap leading-tight overflow-x-auto">
{`Delivered-To: ${email.recipient || 'target-ops@targetdefense.org'}
Received: from ${headers.received_from || email.origin.ip} by mail.targetdefense.org
Authentication-Results: spf=${headers.spf.toLowerCase()} (sender IP: ${email.origin.ip});
 dkim=${headers.dkim.toLowerCase()} header.i=@${email.domain || 'domain'};
 dmarc=${headers.dmarc.toLowerCase()} (p=${headers.dmarc.toLowerCase()})
From: "${email.sender.split('@')[0]}" <${email.sender}>
Return-Path: <${headers.return_path || email.sender}>
Subject: ${email.subject}
Date: ${email.timestamp}
Message-ID: <${email.id.toLowerCase()}@${email.domain || 'forensics'}>
X-Originating-IP: [${email.origin.ip}]
X-ThreatTrace-Score: ${email.fraud_score} / 100
X-ThreatTrace-Verdict: ${email.verdict}`}
            </pre>
          )}

          {activeTab === 'iocs' && (
            <div className="font-mono text-[11px] space-y-2.5">
              <div>
                <span className="text-slate-400 font-bold block mb-1">Embedded Threat Links / Phishing URIs:</span>
                {email.iocs?.urls?.length > 0 ? (
                  email.iocs.urls.map((url, i) => (
                    <div key={i} className="p-1.5 rounded bg-red-950/40 border border-red-800/60 text-red-300 break-all flex items-center justify-between gap-2 mb-1">
                      <span>{url}</span>
                      <span className="text-[9px] px-1 py-0.2 rounded bg-red-900 text-red-200 shrink-0">BLOCKLISTED</span>
                    </div>
                  ))
                ) : (
                  <span className="text-emerald-400">No malicious URLs detected.</span>
                )}
              </div>

              <div>
                <span className="text-slate-400 font-bold block mb-1">Payload SHA256 Signature:</span>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 break-all">
                  {email.iocs?.file_hash || 'SHA256-NOT-EXTRACTED'}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
