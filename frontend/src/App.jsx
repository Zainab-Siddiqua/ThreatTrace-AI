import React, { useState } from 'react';
import initialEmails from './data/demo_emails.json';
import Inbox from './components/Inbox.jsx';
import EmailDetail from './components/EmailDetail.jsx';
import TraceMap from './components/TraceMap.jsx';
import ThreatGraph from './components/ThreatGraph.jsx';
import ReportExporter from './components/ReportExporter.jsx';
import { 
  Shield, 
  ShieldAlert, 
  Activity, 
  Cpu, 
  Radio, 
  Terminal, 
  AlertTriangle, 
  X, 
  Volume2, 
  VolumeX, 
  Layers, 
  Database 
} from 'lucide-react';

// 5 Distinct Realistic Live Attack Templates
const ATTACK_TEMPLATES = [
  {
    templateKey: 'bec_invoice',
    subject: "CRITICAL: Overdue Wire Settlement Invoice #INV-889201 — Final Enforcement",
    sender: "accounts-payable@supplier-global-invoicing.com",
    recipient: "finance.controller@targetdefense.org",
    fraud_score: 95,
    verdict: "MALICIOUS",
    threat_group_id: "Threat Cluster GHOSTWIRE",
    headers: {
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "REJECT",
      return_path: "bounce-invoicing@relay-darknode.nl",
      received_from: "amsterdam-tor-node12.privacy-router.org [185.220.103.11]"
    },
    origin: {
      ip: "185.220.103.11",
      country: "Netherlands",
      city: "Amsterdam",
      lat: 52.3676,
      lng: 4.9041,
      is_vpn_tor: true,
      isp: "Tor Exit Relay / Anonymous Transit Node",
      asn: "AS208323"
    },
    ai_summary: "CRITICAL INCIDENT: Sophisticated Business Email Compromise (BEC) and invoice diversion scheme. Adversaries cloned vendor invoicing headers and embedded altered SWIFT IBAN account routing pointing to an offshore mule account. Origin IP is an active TOR Exit Node in Amsterdam with SPF and DKIM signature failures.",
    body_preview: "URGENT: Outstanding balance of $384,500.00 for Project Helios procurement is past due. Remit payment using updated SWIFT details...",
    full_body: "URGENT NOTIFICATION: Accounts Payable Operations\n\nInvoice ID: #INV-889201 (Project Helios Hardware Milestone)\nAmount Due: $384,500.00 USD\n\nPlease find attached the revised corporate escrow settlement docket. Due to banking partner migration, all wire transfers must be directed to our new European settlement IBAN.\n\nVerify and authorize the settlement release:\nhttps://supplier-global-invoicing.com/settlement/auth?id=INV-889201\n\nFailure to remit within 24 hours will incur statutory interest penalties.\n\nGlobal Supplier Operations Team",
    domain: "supplier-global-invoicing.com",
    iocs: {
      urls: [
        "https://supplier-global-invoicing.com/settlement/auth?id=INV-889201",
        "http://185.220.103.11/exfil/swift_mule.php"
      ],
      c2_ips: [
        "185.220.103.11",
        "45.142.195.12"
      ],
      file_hash: "a4f81c9b209e847c1b5239a0efc689d0246813579bdf0246813579bdf0246813"
    }
  },
  {
    templateKey: 'iam_credential_harvest',
    subject: "CRITICAL: Zero-Day AWS IAM Root Credential Compromise & Exfiltration",
    sender: "security-audit@aws-cloud-security-iam.net",
    recipient: "cloud.architect@targetdefense.org",
    fraud_score: 98,
    verdict: "MALICIOUS",
    threat_group_id: "Threat Cluster GHOSTWIRE",
    headers: {
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "REJECT",
      return_path: "exfil-daemon@bulletproof-dns-sinkhole.is",
      received_from: "tor-relay-exit99.shadow-routing.org [193.148.16.8]"
    },
    origin: {
      ip: "193.148.16.8",
      country: "Iceland",
      city: "Reykjavik",
      lat: 64.1466,
      lng: -21.9426,
      is_vpn_tor: true,
      isp: "Nordic Anonymous Data Relay / Bulletproof TOR",
      asn: "AS60331"
    },
    ai_summary: "CRITICAL INCIDENT: Live zero-day Cloud IAM takeover attack. The adversary spoofed an AWS root credential warning to trick DevOps engineers into authorizing an OAuth backdoor. Origin traced directly to a high-bandwidth TOR exit node in Reykjavik with active C2 beaconing.",
    body_preview: "AWS Security Advisory: An unauthorized session from IP 193.148.16.8 assumed AdministratorAccess role. Re-verify root keys now...",
    full_body: "AWS Security Operations Notification\n\nSecurity Event: Root IAM Credential Exfiltration Detected\nTarget Account: 8491-0391-4920 (Production Kubernetes Cluster)\n\nAn unauthorized identity assumed Administrative Role credentials via an anomalous endpoint. You must immediately invalidate active access tokens and re-authorize through the emergency IAM bastion:\n\nEmergency Auth URL: https://aws-cloud-security-iam.net/auth/verify?session=root_token_99x\n\nFailure to verify within 15 minutes will trigger automatic VPC quarantine.\n\nAWS Cloud Security Operations Team",
    domain: "aws-cloud-security-iam.net",
    iocs: {
      urls: [
        "https://aws-cloud-security-iam.net/auth/verify?session=root_token_99x",
        "http://193.148.16.8/sinkhole/token_harvest.php"
      ],
      c2_ips: [
        "193.148.16.8",
        "45.154.255.88"
      ],
      file_hash: "9b724b10499cfd2fbdf17be47228ecf759600e12d4a13d33190dfeb693b8e4f1"
    }
  },
  {
    templateKey: 'courier_delivery_scam',
    subject: "Urgent Delivery Exception: Consignment #DHL-93821049-EX Parcel Retained at Customs",
    sender: "dispatch-notification@express-courier-clearance.cc",
    recipient: "logistics.lead@targetdefense.org",
    fraud_score: 92,
    verdict: "MALICIOUS",
    threat_group_id: "Threat Cluster GHOSTWIRE",
    headers: {
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "REJECT",
      return_path: "postmaster@express-courier-clearance.cc",
      received_from: "vps-edge-host03.bulletproof-transit.de [109.205.213.77]"
    },
    origin: {
      ip: "109.205.213.77",
      country: "Germany",
      city: "Frankfurt",
      lat: 50.1109,
      lng: 8.6821,
      is_vpn_tor: true,
      isp: "Offshore Bulletproof Hosting Ltd",
      asn: "AS49981"
    },
    ai_summary: "HIGH RISK: Malicious shipment delivery lure delivering an executable payload disguised as an international customs clearance receipt. Heuristic analysis identified obfuscated PowerShell staging scripts designed to deploy an infostealer backdoor. Traced to bulletproof hosting in Frankfurt.",
    body_preview: "Your international freight shipment has been detained at customs clearance due to unpaid duty taxes. Download the release waiver form...",
    full_body: "Express International Courier Operations\n\nConsignment Tracking: #DHL-93821049-EX\nDestination: TargetDefense HQ Receiving Dock\n\nYour priority express consignment could not be delivered and is currently held at Frankfurt Air Cargo Terminal due to missing customs declaration documentation.\n\nPlease inspect the electronic clearance receipt and release waiver:\nhttps://express-courier-clearance.cc/track/DHL-93821049-EX\n\nUnclaimed parcels will be returned to the origin sender in 48 hours.\n\nExpress Dispatch & Logistics Management",
    domain: "express-courier-clearance.cc",
    iocs: {
      urls: [
        "https://express-courier-clearance.cc/track/DHL-93821049-EX",
        "http://109.205.213.77/payload/customs_docs.iso"
      ],
      c2_ips: [
        "109.205.213.77",
        "194.26.29.112"
      ],
      file_hash: "7d62bc89a3f01e23c914ef056b27d490192837465afbecd0192837465afbecd0"
    }
  },
  {
    templateKey: 'hr_payroll_scam',
    subject: "CONFIDENTIAL: Mandatory Review of Updated 2026 Executive Payroll & Bonus Policy",
    sender: "hr-benefits-portal@people-workday-secure.org",
    recipient: "staff-engineering@targetdefense.org",
    fraud_score: 96,
    verdict: "MALICIOUS",
    threat_group_id: "Threat Cluster GHOSTWIRE",
    headers: {
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "REJECT",
      return_path: "bounce-hr@m247-transit.ro",
      received_from: "relay-gateway-node7.m247-hosting.ro [185.191.34.198]"
    },
    origin: {
      ip: "185.191.34.198",
      country: "Romania",
      city: "Bucharest",
      lat: 44.4268,
      lng: 26.1025,
      is_vpn_tor: true,
      isp: "M247 Anonymous Gateway Infrastructure",
      asn: "AS9009"
    },
    ai_summary: "CRITICAL INCIDENT: Targeted spear-phishing campaign leveraging corporate HR urgency. Adversaries created a high-fidelity clone of the Workday Single Sign-On (SSO) login portal designed to intercept session cookies and bypass FIDO/U2F multi-factor authentication via an AiTM reverse-proxy.",
    body_preview: "All employees are required to review and digitally sign the revised Q3 bonus schedules and equity compensation schedule before September 15...",
    full_body: "Human Resources & Total Rewards Notice\n\nSubject: FY2026 Compensation & Performance Bonus Policy Update\nTarget Employee: Corporate Engineering & Operations Staff\n\nManagement has published the revised annual compensation structure, performance multipliers, and updated healthcare benefit selections for the upcoming fiscal quarter.\n\nReview and electronically sign your individual compensation schedule here:\nhttps://people-workday-secure.org/sso/hr-portal?auth_token=q3_bonus_981\n\nAll acknowledgments must be finalized through the secure HR portal.\n\nCorporate People & Culture Department",
    domain: "people-workday-secure.org",
    iocs: {
      urls: [
        "https://people-workday-secure.org/sso/hr-portal?auth_token=q3_bonus_981",
        "http://185.191.34.198/proxy/workday_harvest"
      ],
      c2_ips: [
        "185.191.34.198",
        "91.240.118.45"
      ],
      file_hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    }
  },
  {
    templateKey: 'it_vpn_patch_scam',
    subject: "SECURITY ADVISORY: Immediate Action - Zero-Day Patch for Enterprise VPN Gateway",
    sender: "itsupport-emergency@global-it-helpdesk-auth.io",
    recipient: "soc-team@targetdefense.org",
    fraud_score: 97,
    verdict: "MALICIOUS",
    threat_group_id: "Threat Cluster GHOSTWIRE",
    headers: {
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "REJECT",
      return_path: "it-alert@shadow-transit.bg",
      received_from: "border-gateway-gw01.shadow-routing.bg [45.154.255.67]"
    },
    origin: {
      ip: "45.154.255.67",
      country: "Bulgaria",
      city: "Sofia",
      lat: 42.6977,
      lng: 23.3219,
      is_vpn_tor: true,
      isp: "Shadow Network Services / Bulletproof Transit",
      asn: "AS48693"
    },
    ai_summary: "CRITICAL INCIDENT: IT service-desk impersonation distributing a rogue VPN update package. The binary installs a persistent Remote Access Trojan (RAT) and establishes encrypted tunnels back to command-and-control infrastructure in Sofia, Bulgaria. Cryptographic checks failed across all protocols.",
    body_preview: "Urgent IT Action Required: A critical remote code execution flaw (CVE-2026-38192) has been detected in company VPN endpoints. Apply hotfix now...",
    full_body: "Enterprise IT Support & Infrastructure Directorate\n\nCritical Notice: Urgent Client Security Update (CVE-2026-38192)\nThreat Level: SEVERITY 9.8 / CRITICAL RCE EXPLOITATION\n\nA remote code execution vulnerability is actively being targeted against corporate remote access endpoints. All connected devices must deploy the hotfix patch immediately to prevent network disconnection.\n\nDownload and install the verified client hotfix package:\nhttps://global-it-helpdesk-auth.io/patch/cve-2026-38192/install\n\nUnpatched devices will be quarantined from the enterprise VPN boundary in 30 minutes.\n\nGlobal IT Service Desk & Infrastructure Security",
    domain: "global-it-helpdesk-auth.io",
    iocs: {
      urls: [
        "https://global-it-helpdesk-auth.io/patch/cve-2026-38192/install",
        "http://45.154.255.67/c2/vpn_beacon"
      ],
      c2_ips: [
        "45.154.255.67",
        "185.220.101.99"
      ],
      file_hash: "2c624232cdd221771294dfbb310aca000a0df6ec9b5feb9bb7dd73cc4f853be3"
    }
  }
];

export default function App() {
  const [emails, setEmails] = useState(initialEmails);
  const [selectedEmail, setSelectedEmail] = useState(initialEmails[0]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [attackAlert, setAttackAlert] = useState(null);
  const [soundMuted, setSoundMuted] = useState(false);
  const [lastTemplateIndex, setLastTemplateIndex] = useState(-1);

  // Simulate Live Phishing / Ransomware Attack with 5 Randomized Templates
  const handleSimulateAttack = () => {
    if (isSimulating) return;

    setIsSimulating(true);

    setTimeout(() => {
      // Pick a random template different from the last one if possible
      let availableIndices = ATTACK_TEMPLATES.map((_, i) => i);
      if (lastTemplateIndex >= 0 && ATTACK_TEMPLATES.length > 1) {
        availableIndices = availableIndices.filter(i => i !== lastTemplateIndex);
      }
      const randomIndex = availableIndices[Math.floor(Math.random() * availableIndices.length)];
      setLastTemplateIndex(randomIndex);

      const template = ATTACK_TEMPLATES[randomIndex];
      const attackId = `EML-2026-${Math.floor(1000 + Math.random() * 9000)}`;
      
      const newAttack = {
        ...template,
        id: attackId,
        timestamp: new Date().toISOString()
      };

      setEmails((prev) => [newAttack, ...prev]);
      setSelectedEmail(newAttack);
      setIsSimulating(false);

      // Trigger Alert Banner
      setAttackAlert({
        id: attackId,
        subject: newAttack.subject,
        ip: newAttack.origin.ip,
        threatGroup: newAttack.threat_group_id,
        timestamp: new Date().toLocaleTimeString()
      });

      // Play audio alert tone (Web Audio API synth beep)
      if (!soundMuted && typeof window !== 'undefined' && (window.AudioContext || window.webkitAudioContext)) {
        try {
          const AudioContextClass = window.AudioContext || window.webkitAudioContext;
          const audioCtx = new AudioContextClass();
          const osc = audioCtx.createOscillator();
          const gain = audioCtx.createGain();
          osc.type = 'sawtooth';
          osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
          osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.3);
          gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
          osc.connect(gain);
          gain.connect(audioCtx.destination);
          osc.start();
          osc.stop(audioCtx.currentTime + 0.3);
        } catch (e) {
          // Audio autoplay permissions fallback
        }
      }
    }, 3000);
  };

  // Quick stats calculations
  const totalEmails = emails.length;
  const criticalCount = emails.filter((e) => e.fraud_score > 70).length;
  const torCount = emails.filter((e) => e.origin?.is_vpn_tor).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans cyber-bg selection:bg-cyan-500 selection:text-slate-950">
      
      {/* Top Header & Alert Container (Stacked in normal flex flow) */}
      <div className="sticky top-0 z-50 w-full flex flex-col">
        
        {/* Flashing Red Attack Alert Banner - Stacked directly above header in normal flow */}
        {attackAlert && (
          <div className="bg-red-950/95 border-b border-red-500/80 text-red-100 px-4 py-2 flex items-center justify-between animate-flash-alert shadow-[0_0_20px_rgba(239,68,68,0.5)] font-mono text-xs backdrop-blur-md">
            <div className="flex items-center space-x-3 overflow-hidden mr-4">
              <span className="p-1 rounded bg-red-600 text-white animate-ping shrink-0">
                <ShieldAlert className="w-4 h-4" />
              </span>
              <div className="truncate">
                <span className="font-bold text-red-200 uppercase tracking-wide">
                  [HIGH PRIORITY ALERT] ZERO-DAY ATTACK INJECTED:
                </span>{' '}
                <span className="text-white font-semibold">{attackAlert.subject}</span>{' '}
                <span className="text-red-300">
                  (Origin IP: <strong className="text-white underline">{attackAlert.ip}</strong> | Actor: <strong className="text-purple-300">{attackAlert.threatGroup}</strong>)
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                onClick={() => setSoundMuted(!soundMuted)}
                className="p-1 rounded bg-red-900/80 hover:bg-red-800 text-red-200 transition"
                title={soundMuted ? 'Unmute alerts' : 'Mute alerts'}
              >
                {soundMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
              </button>
              <button
                onClick={() => setAttackAlert(null)}
                className="px-2 py-0.5 rounded bg-red-800 hover:bg-red-700 text-white font-bold transition flex items-center gap-1 text-[11px]"
              >
                <X className="w-3.5 h-3.5" /> DISMISS
              </button>
            </div>
          </div>
        )}

        {/* Top Header Bar */}
        <header className="bg-slate-900/95 border-b border-slate-800 px-4 py-3 backdrop-blur-md shadow-lg">
          <div className="max-w-[1920px] mx-auto flex flex-wrap items-center justify-between gap-3">
            
            {/* Brand & Subtitle */}
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.3)]">
                <Shield className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-base font-bold text-slate-100 tracking-tight font-mono flex items-center gap-2">
                    <span>ThreatTrace AI</span>
                    <span className="text-slate-500 font-normal">|</span>
                    <span className="text-cyan-400 text-xs font-normal tracking-wider">CYBER-FORENSICS ENGINE</span>
                  </h1>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  AI-POWERED SPEAR-PHISHING DETECTION &amp; GEOSPATIAL THREAT ATTRIBUTION
                </div>
              </div>
            </div>

            {/* Center SOC Status Badges */}
            <div className="hidden lg:flex items-center space-x-4 font-mono text-xs">
              <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-950 border border-emerald-500/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                <span className="font-bold tracking-wider">SOC PIPELINE: ACTIVE</span>
              </div>
              <div className="text-slate-400 text-[11px] flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>NODE: <strong className="text-slate-200">ASIA-SOUTH-1</strong></span>
              </div>
              <div className="text-slate-400 text-[11px] flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-purple-400" />
                <span>TEAM: <strong className="text-slate-200">SIH-THREATTRACE</strong></span>
              </div>
            </div>

            {/* Quick HUD Metrics */}
            <div className="flex items-center space-x-3 font-mono text-xs">
              <div className="px-2.5 py-1 rounded bg-slate-950/80 border border-slate-800 text-slate-300 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                <span>QUEUED: <strong className="text-cyan-300">{totalEmails}</strong></span>
              </div>
              <div className="px-2.5 py-1 rounded bg-slate-950/80 border border-red-900/60 text-red-300 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                <span>CRITICAL: <strong className="text-red-400">{criticalCount}</strong></span>
              </div>
              <div className="px-2.5 py-1 rounded bg-slate-950/80 border border-amber-900/60 text-amber-300 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-amber-400" />
                <span>TOR EXITS: <strong className="text-amber-300">{torCount}</strong></span>
              </div>
            </div>
          </div>
        </header>
      </div>

      {/* Main 3-Column SOC Grid Layout */}
      <main className="flex-1 p-3 md:p-4 max-w-[1920px] mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 md:gap-4 items-start">
          
          {/* Column 1: Left 30% (Inbox Triage Queue) */}
          <div className="lg:col-span-4 xl:col-span-4 h-[calc(100vh-135px)] min-h-[600px] flex flex-col">
            <Inbox
              emails={emails}
              selectedEmail={selectedEmail}
              onSelectEmail={setSelectedEmail}
              onSimulateAttack={handleSimulateAttack}
              isSimulating={isSimulating}
            />
          </div>

          {/* Column 2: Center 40% (Email Forensic Detail & Trace Map) */}
          <div className="lg:col-span-5 xl:col-span-5 flex flex-col space-y-3 md:space-y-4">
            <EmailDetail email={selectedEmail} />
            <TraceMap email={selectedEmail} />
          </div>

          {/* Column 3: Right 30% (Threat Graph & Forensic PDF Exporter) */}
          <div className="lg:col-span-3 xl:col-span-3 flex flex-col space-y-3 md:space-y-4">
            <ThreatGraph email={selectedEmail} />
            <ReportExporter email={selectedEmail} />
          </div>

        </div>
      </main>

      {/* Bottom Forensic Status Footer */}
      <footer className="bg-slate-950/90 border-t border-slate-900 px-4 py-1.5 font-mono text-[10px] text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-3">
          <span className="flex items-center gap-1 text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span>
            CRYPTOGRAPHIC ENVELOPE VERIFIED
          </span>
          <span>•</span>
          <span>TELEMETRY: REAL-TIME STREAMING</span>
          <span>•</span>
          <span>LATENCY: 14ms</span>
        </div>
        <div>
          <span>ThreatTrace AI Forensics Engine © 2026 | SIH Defense Division</span>
        </div>
      </footer>
    </div>
  );
}
