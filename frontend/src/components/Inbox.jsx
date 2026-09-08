import React, { useState } from 'react';
import { 
  Inbox as InboxIcon, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Zap, 
  Filter, 
  Clock, 
  Globe, 
  Lock, 
  Radio
} from 'lucide-react';

export default function Inbox({ emails, selectedEmail, onSelectEmail, onSimulateAttack, isSimulating }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState('ALL'); // 'ALL', 'MALICIOUS', 'SUSPICIOUS', 'BENIGN'

  const filteredEmails = emails.filter((email) => {
    const matchesSearch = 
      email.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.sender.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.origin.city.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.origin.country.toLowerCase().includes(searchQuery.toLowerCase());

    if (filterVerdict === 'ALL') return matchesSearch;
    return matchesSearch && email.verdict === filterVerdict;
  });

  const getScoreBadge = (score) => {
    if (score > 70) {
      return 'bg-red-950/80 text-red-400 border-red-700/80';
    } else if (score >= 40) {
      return 'bg-amber-950/80 text-amber-400 border-amber-700/80';
    } else {
      return 'bg-emerald-950/80 text-emerald-400 border-emerald-700/80';
    }
  };

  return (
    <div className="bg-slate-900/90 rounded-lg border border-slate-800 p-3 flex flex-col h-full shadow-lg">
      {/* Inbox Header */}
      <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800 font-mono">
        <div className="flex items-center space-x-2 text-cyan-400 text-xs">
          <InboxIcon className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold tracking-wider">TRIAGE QUEUE ({filteredEmails.length})</span>
        </div>

        {/* Live Attack Simulation Button */}
        <button
          onClick={onSimulateAttack}
          disabled={isSimulating}
          className={`px-2.5 py-1 rounded text-xs font-mono font-bold flex items-center gap-1.5 transition ${
            isSimulating
              ? 'bg-red-950 text-red-300 border border-red-600 animate-pulse cursor-not-allowed'
              : 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-900/40 active:scale-95'
          }`}
          title="Simulate incoming zero-day spear-phishing attack"
        >
          <Zap className={`w-3.5 h-3.5 ${isSimulating ? 'animate-bounce' : ''}`} />
          <span>{isSimulating ? 'Injecting Attack (3s)...' : 'Simulate Live Attack'}</span>
        </button>
      </div>

      {/* Simulation Progress Bar */}
      {isSimulating && (
        <div className="mb-2 p-2 rounded bg-red-950/60 border border-red-800/80 text-[11px] font-mono text-red-300 animate-pulse flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-red-400 animate-ping" />
            <span>SYNCHRONIZING ZERO-DAY PAYLOAD...</span>
          </span>
          <span className="font-bold">ARMED</span>
        </div>
      )}

      {/* Search Input */}
      <div className="relative mb-2">
        <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 transform -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter by subject, sender, IP, or city..."
          className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition font-mono"
        />
      </div>

      {/* Verdict Filter Buttons */}
      <div className="flex items-center gap-1 mb-3 text-[10px] font-mono">
        <button
          onClick={() => setFilterVerdict('ALL')}
          className={`px-2 py-0.5 rounded transition ${
            filterVerdict === 'ALL'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
              : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          ALL
        </button>
        <button
          onClick={() => setFilterVerdict('MALICIOUS')}
          className={`px-2 py-0.5 rounded transition ${
            filterVerdict === 'MALICIOUS'
              ? 'bg-red-950 text-red-300 border border-red-700 font-bold'
              : 'bg-slate-950 text-slate-400 hover:text-red-300 border border-slate-800'
          }`}
        >
          CRITICAL &gt;70%
        </button>
        <button
          onClick={() => setFilterVerdict('SUSPICIOUS')}
          className={`px-2 py-0.5 rounded transition ${
            filterVerdict === 'SUSPICIOUS'
              ? 'bg-amber-950 text-amber-300 border border-amber-700 font-bold'
              : 'bg-slate-950 text-slate-400 hover:text-amber-300 border border-slate-800'
          }`}
        >
          SUSPICIOUS
        </button>
        <button
          onClick={() => setFilterVerdict('BENIGN')}
          className={`px-2 py-0.5 rounded transition ${
            filterVerdict === 'BENIGN'
              ? 'bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold'
              : 'bg-slate-950 text-slate-400 hover:text-emerald-300 border border-slate-800'
          }`}
        >
          BENIGN
        </button>
      </div>

      {/* Email Cards List */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-1">
        {filteredEmails.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-xs font-mono">
            No matching security events found.
          </div>
        ) : (
          filteredEmails.map((email) => {
            const isSelected = selectedEmail?.id === email.id;
            const isMalicious = email.fraud_score > 70;
            const isSuspicious = email.fraud_score >= 40 && email.fraud_score <= 70;

            return (
              <div
                key={email.id}
                onClick={() => onSelectEmail(email)}
                className={`p-2.5 rounded-lg border transition cursor-pointer relative ${
                  isSelected
                    ? 'bg-slate-800/90 border-cyan-500 shadow-md shadow-cyan-950/40 ring-1 ring-cyan-500/40'
                    : 'bg-slate-950/60 border-slate-800/90 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                {/* Active indicator bar */}
                {isSelected && (
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyan-400 rounded-l-lg shadow-[0_0_8px_#06b6d4]"></div>
                )}

                {/* Card Top: ID & Fraud Score Badge */}
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-mono text-slate-400 font-bold">
                      {email.id}
                    </span>
                    {email.origin.is_vpn_tor && (
                      <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-red-950 text-red-400 border border-red-800 font-bold">
                        TOR
                      </span>
                    )}
                  </div>

                  {/* Risk Score Badge */}
                  <div className={`px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${getScoreBadge(email.fraud_score)}`}>
                    {email.fraud_score}% • {email.verdict}
                  </div>
                </div>

                {/* Subject */}
                <h3 className="text-xs font-semibold text-slate-100 line-clamp-1 mb-1 font-sans">
                  {email.subject}
                </h3>

                {/* Sender */}
                <div className="text-[11px] font-mono text-slate-400 truncate mb-2">
                  {email.sender}
                </div>

                {/* Card Footer: Origin & Timestamp */}
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1.5 border-t border-slate-800/60">
                  <span className="flex items-center gap-1 text-slate-400">
                    <Globe className="w-3 h-3 text-cyan-500" />
                    <span>{email.origin.city}, {email.origin.country}</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    <span>{new Date(email.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
