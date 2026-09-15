from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Dict, Any
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from intelligence.attribution_graph import threat_engine, ThreatGraphEngine
import intelligence.attribution_graph as graph_module

# Docs disabled on default root to allow custom dark theme injection
app = FastAPI(
    title="ThreatTrace Intelligence API",
    description="Graph-based threat infrastructure and syndicate correlation engine",
    version="2.0.0",
    docs_url=None
)

def reset_default_nodes():
    graph_module.threat_engine = ThreatGraphEngine()
    # Syndicate 1: Microsoft/Azure Spoofing Syndicate
    graph_module.threat_engine.ingest_artifact({
        "email_id": "MSG-101",
        "sender": "ceo-update@m1crosoft-auth.com",
        "domain": "m1crosoft-auth.com",
        "origin_ip": "185.220.101.5",
        "location": {"country": "NL", "city": "Amsterdam", "isp": "HostPalace Web Services"},
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "domain_age_days": 12,
        "urls": ["https://m1crosoft-auth.com/portal/login.php"],
        "fraud_score": 0.94
    })
    graph_module.threat_engine.ingest_artifact({
        "email_id": "MSG-102",
        "sender": "security@azure-cloud-renew.net",
        "domain": "azure-cloud-renew.net",
        "origin_ip": "185.220.101.5",
        "location": {"country": "NL", "city": "Amsterdam", "isp": "HostPalace Web Services"},
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "domain_age_days": 8,
        "urls": ["https://azure-cloud-renew.net/verify"],
        "fraud_score": 0.91
    })
    # Syndicate 2: Internal Payroll Phishing Syndicate
    graph_module.threat_engine.ingest_artifact({
        "email_id": "MSG-103",
        "sender": "hr-verify@payroll-internal.org",
        "domain": "payroll-internal.org",
        "origin_ip": "194.26.29.112",
        "location": {"country": "RU", "city": "St Petersburg", "isp": "Selectel ISP"},
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "domain_age_days": 15,
        "urls": ["https://payroll-internal.org/salary-slip.pdf.exe"],
        "fraud_score": 0.88
    })
    graph_module.threat_engine.ingest_artifact({
        "email_id": "MSG-104",
        "sender": "payroll-dept@payroll-internal.org",
        "domain": "payroll-internal.org",
        "origin_ip": "194.26.29.112",
        "location": {"country": "RU", "city": "St Petersburg", "isp": "Selectel ISP"},
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "domain_age_days": 15,
        "urls": ["https://payroll-internal.org/salary-slip.pdf.exe"],
        "fraud_score": 0.96
    })

reset_default_nodes()

class EmailForensicArtifact(BaseModel):
    email_id: str = Field(..., description="Unique email message identifier", example="MSG-9042")
    sender: str = Field(..., description="Sender persona email address", example="urgent-security@m1crosoft-auth.com")
    domain: str = Field(..., description="Fully qualified sender domain", example="m1crosoft-auth.com")
    origin_ip: str = Field(..., description="Originating transit/infrastructure IP", example="185.220.101.5")
    location: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Geospatial trace context (country, city, isp)",
        example={"country": "NL", "city": "Amsterdam", "isp": "HostPalace Web Services"}
    )
    spf_status: str = Field(default="FAIL", description="SPF authentication verdict (PASS/FAIL)", example="FAIL")
    dkim_status: str = Field(default="FAIL", description="DKIM cryptographic signature status (PASS/FAIL)", example="FAIL")
    dmarc_status: str = Field(default="FAIL", description="DMARC alignment policy status (PASS/FAIL)", example="FAIL")
    domain_age_days: Optional[int] = Field(default=None, description="Age of sender domain in days", example=12)
    urls: Optional[List[str]] = Field(
        default=None,
        description="Suspicious payload or credential harvesting links",
        example=["https://m1crosoft-auth.com/portal/login.php"]
    )
    fraud_score: float = Field(..., description="Calculated threat fraud risk score (0.0 - 1.0)", example=0.94)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email_id": "MSG-9042",
                "sender": "urgent-security@m1crosoft-auth.com",
                "domain": "m1crosoft-auth.com",
                "origin_ip": "185.220.101.5",
                "location": {
                    "country": "NL",
                    "city": "Amsterdam",
                    "isp": "HostPalace Web Services"
                },
                "spf_status": "FAIL",
                "dkim_status": "FAIL",
                "dmarc_status": "FAIL",
                "domain_age_days": 12,
                "urls": [
                    "https://m1crosoft-auth.com/portal/login.php"
                ],
                "fraud_score": 0.94
            }
        }
    }

    @model_validator(mode="before")
    @classmethod
    def handle_legacy_fields(cls, data: Any):
        if isinstance(data, dict):
            if "fraud_score" not in data and "threat_score" in data:
                data["fraud_score"] = data["threat_score"]
            if "spf_status" not in data:
                data["spf_status"] = "FAIL"
            if "dkim_status" not in data:
                data["dkim_status"] = "FAIL"
            if "dmarc_status" not in data:
                data["dmarc_status"] = "FAIL"
        return data

@app.get("/docs", include_in_schema=False)
def custom_dark_swagger_ui_html():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ThreatTrace Intelligence // API Documentation</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
      <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
      <style>
        *, *::before, *::after {
          box-sizing: border-box;
        }
        body {
          background: radial-gradient(circle at 10% 20%, #0d1322 0%, #05070e 90%) fixed !important;
          background-color: #0b0f19 !important;
          color: #f1f5f9 !important;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
          margin: 0;
          padding: 0;
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
        }

        /* Swagger UI Base Overrides */
        .swagger-ui {
          color: #f1f5f9 !important;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }
        .swagger-ui .wrapper {
          max-width: 1180px !important;
          padding: 24px 20px 48px !important;
        }
        .swagger-ui .topbar {
          display: none !important;
        }

        /* Top Header Nav Banner */
        .api-nav-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          background: rgba(15, 23, 42, 0.82);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 12px;
          padding: 14px 20px;
          margin-bottom: 24px;
        }
        .api-nav-brand {
          font-family: 'JetBrains Mono', monospace;
          font-weight: 800;
          font-size: 0.95rem;
          letter-spacing: 1.5px;
          color: #f8fafc;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .api-nav-brand span.highlight {
          color: #38bdf8;
          text-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }
        .api-nav-link {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.78rem;
          color: #38bdf8;
          text-decoration: none;
          background: rgba(14, 165, 233, 0.12);
          border: 1px solid rgba(56, 189, 248, 0.35);
          padding: 6px 14px;
          border-radius: 6px;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .api-nav-link:hover {
          background: rgba(14, 165, 233, 0.25);
          border-color: #38bdf8;
          box-shadow: 0 0 14px rgba(56, 189, 248, 0.3);
          transform: translateY(-1px);
        }

        /* Info Block */
        .swagger-ui .info {
          margin: 0 0 28px 0 !important;
          background: rgba(15, 23, 42, 0.75) !important;
          backdrop-filter: blur(16px) !important;
          -webkit-backdrop-filter: blur(16px) !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          border-radius: 12px !important;
          padding: 24px !important;
          box-shadow: 0 4px 24px rgba(0, 0, 0, 0.35) !important;
        }
        .swagger-ui .info .title {
          font-family: 'JetBrains Mono', monospace !important;
          font-weight: 800 !important;
          color: #38bdf8 !important;
          letter-spacing: 1.5px !important;
          font-size: 1.65rem !important;
          text-shadow: 0 0 16px rgba(56, 189, 248, 0.35) !important;
          margin-bottom: 8px !important;
        }
        .swagger-ui .info .title small {
          background: rgba(14, 165, 233, 0.15) !important;
          color: #38bdf8 !important;
          border: 1px solid rgba(56, 189, 248, 0.4) !important;
          border-radius: 9999px !important;
          padding: 3px 10px !important;
          font-size: 0.72rem !important;
          font-family: 'JetBrains Mono', monospace !important;
          letter-spacing: 0.5px !important;
          vertical-align: middle !important;
        }
        .swagger-ui .info .description,
        .swagger-ui .info p {
          color: #94a3b8 !important;
          font-size: 0.92rem !important;
          line-height: 1.6 !important;
          margin: 10px 0 0 !important;
        }
        .swagger-ui .info a {
          color: #38bdf8 !important;
          text-decoration: none !important;
        }
        .swagger-ui .info a:hover {
          text-decoration: underline !important;
        }
        .swagger-ui .info .base-url {
          color: #64748b !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.78rem !important;
        }

        /* Section Tags */
        .swagger-ui .opblock-tag-section {
          margin-bottom: 24px !important;
        }
        .swagger-ui .opblock-tag {
          color: #f1f5f9 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 1.05rem !important;
          letter-spacing: 0.5px !important;
          border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
          padding: 10px 0 !important;
          margin-bottom: 12px !important;
        }
        .swagger-ui .opblock-tag:hover {
          color: #38bdf8 !important;
        }
        .swagger-ui .opblock-tag small {
          color: #64748b !important;
          font-family: 'Inter', sans-serif !important;
          font-size: 0.8rem !important;
          margin-left: 10px !important;
        }

        /* Operation Blocks (Section Cards) */
        .swagger-ui .opblock {
          background: #0f172a !important;
          border: 1px solid rgba(255, 255, 255, 0.12) !important;
          border-radius: 10px !important;
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35) !important;
          margin: 0 0 14px !important;
          transition: border-color 0.2s, box-shadow 0.2s !important;
          overflow: hidden !important;
        }
        .swagger-ui .opblock:hover {
          border-color: rgba(56, 189, 248, 0.5) !important;
        }
        .swagger-ui .opblock.is-open {
          background: #111c35 !important;
          border-color: rgba(56, 189, 248, 0.6) !important;
          box-shadow: 0 0 20px rgba(14, 165, 233, 0.2) !important;
        }
        .swagger-ui .opblock .opblock-summary {
          padding: 14px 20px !important;
          display: flex !important;
          align-items: center !important;
          border-bottom: none !important;
          cursor: pointer !important;
          background: rgba(15, 23, 42, 0.95) !important;
        }
        .swagger-ui .opblock.is-open .opblock-summary {
          border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
          background: rgba(20, 30, 52, 0.98) !important;
        }
        .swagger-ui .opblock .opblock-summary-path,
        .swagger-ui .opblock .opblock-summary-path a,
        .swagger-ui .opblock .opblock-summary-path span,
        .swagger-ui .opblock .opblock-summary-path__deprecated {
          color: #ffffff !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.96rem !important;
          font-weight: 700 !important;
          text-decoration: none !important;
          letter-spacing: 0.3px !important;
        }
        .swagger-ui .opblock .opblock-summary-description {
          color: #e2e8f0 !important;
          font-family: 'Inter', sans-serif !important;
          font-size: 0.86rem !important;
          font-weight: 500 !important;
          margin-left: 16px !important;
          opacity: 0.95 !important;
        }
        .swagger-ui .opblock .arrow {
          fill: #cbd5e1 !important;
          transition: transform 0.2s, fill 0.2s !important;
        }
        .swagger-ui .opblock:hover .arrow {
          fill: #38bdf8 !important;
        }

        /* HTTP Method Badges - High Contrast Solid Badges */
        .swagger-ui .opblock .opblock-summary-method {
          font-family: 'JetBrains Mono', monospace !important;
          font-weight: 800 !important;
          font-size: 0.74rem !important;
          letter-spacing: 1px !important;
          border-radius: 6px !important;
          padding: 6px 14px !important;
          min-width: 74px !important;
          text-align: center !important;
          text-shadow: none !important;
        }

        /* GET Method: Vivid Sky Blue with White Text */
        .swagger-ui .opblock-get {
          border-color: rgba(14, 165, 233, 0.35) !important;
        }
        .swagger-ui .opblock-get .opblock-summary {
          background: rgba(14, 165, 233, 0.08) !important;
        }
        .swagger-ui .opblock-get .opblock-summary-method {
          background: #0284c7 !important;
          color: #ffffff !important;
          border: 1px solid #38bdf8 !important;
          box-shadow: 0 0 12px rgba(14, 165, 233, 0.4) !important;
        }
        .swagger-ui .opblock-get:hover {
          border-color: #38bdf8 !important;
        }

        /* POST Method: Vivid Emerald with White Text */
        .swagger-ui .opblock-post {
          border-color: rgba(16, 185, 129, 0.35) !important;
        }
        .swagger-ui .opblock-post .opblock-summary {
          background: rgba(16, 185, 129, 0.08) !important;
        }
        .swagger-ui .opblock-post .opblock-summary-method {
          background: #059669 !important;
          color: #ffffff !important;
          border: 1px solid #10b981 !important;
          box-shadow: 0 0 12px rgba(16, 185, 129, 0.4) !important;
        }
        .swagger-ui .opblock-post:hover {
          border-color: #10b981 !important;
        }

        /* DELETE Method */
        .swagger-ui .opblock-delete .opblock-summary-method {
          background: rgba(244, 63, 94, 0.18) !important;
          color: #fb7185 !important;
          border: 1px solid rgba(244, 63, 94, 0.5) !important;
          box-shadow: 0 0 10px rgba(244, 63, 94, 0.2) !important;
        }

        /* PUT / PATCH Methods */
        .swagger-ui .opblock-put .opblock-summary-method,
        .swagger-ui .opblock-patch .opblock-summary-method {
          background: rgba(245, 158, 11, 0.18) !important;
          color: #fbbf24 !important;
          border: 1px solid rgba(245, 158, 11, 0.5) !important;
          box-shadow: 0 0 10px rgba(245, 158, 11, 0.2) !important;
        }

        /* Opblock Body Content */
        .swagger-ui .opblock-body {
          background: #090e1a !important;
          padding: 20px !important;
        }
        .swagger-ui .opblock-section-header {
          background: rgba(15, 23, 42, 0.75) !important;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
          box-shadow: none !important;
          padding: 10px 16px !important;
          border-radius: 6px !important;
          margin-bottom: 12px !important;
        }
        .swagger-ui .opblock-section-header h4 {
          color: #f1f5f9 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.78rem !important;
          letter-spacing: 0.8px !important;
          text-transform: uppercase !important;
        }
        .swagger-ui .opblock-description-wrapper,
        .swagger-ui .opblock-external-docs-wrapper,
        .swagger-ui .opblock-title_normal {
          color: #94a3b8 !important;
        }

        /* Parameters Table */
        .swagger-ui table {
          background: transparent !important;
          color: #f1f5f9 !important;
        }
        .swagger-ui table thead tr td,
        .swagger-ui table thead tr th {
          color: #94a3b8 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.72rem !important;
          text-transform: uppercase !important;
          letter-spacing: 0.8px !important;
          border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
          padding: 10px 12px !important;
        }
        .swagger-ui .parameter__name {
          color: #38bdf8 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-weight: 600 !important;
          font-size: 0.84rem !important;
        }
        .swagger-ui .parameter__type {
          color: #a855f7 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.75rem !important;
        }
        .swagger-ui .parameter__in {
          color: #64748b !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.72rem !important;
        }
        .swagger-ui .parameter__deprecated {
          color: #ef4444 !important;
        }

        /* Inputs, Textareas, Selects */
        .swagger-ui input[type="text"],
        .swagger-ui input[type="password"],
        .swagger-ui input[type="search"],
        .swagger-ui input[type="email"],
        .swagger-ui input[type="file"],
        .swagger-ui textarea,
        .swagger-ui select {
          background: #020617 !important;
          border: 1px solid #334155 !important;
          border-radius: 6px !important;
          color: #f1f5f9 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.84rem !important;
          padding: 8px 12px !important;
          outline: none !important;
          transition: border-color 0.2s, box-shadow 0.2s !important;
        }
        .swagger-ui input[type="text"]:focus,
        .swagger-ui textarea:focus,
        .swagger-ui select:focus {
          border-color: #38bdf8 !important;
          box-shadow: 0 0 10px rgba(56, 189, 248, 0.25) !important;
        }

        /* Action Buttons: Try it out, Execute, Cancel */
        .swagger-ui .btn {
          font-family: 'Inter', sans-serif !important;
          font-weight: 600 !important;
          border-radius: 6px !important;
          padding: 8px 16px !important;
          font-size: 0.82rem !important;
          letter-spacing: 0.3px !important;
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
          cursor: pointer !important;
        }
        .swagger-ui .btn.try-out__btn {
          background: rgba(30, 41, 59, 0.65) !important;
          border: 1px solid rgba(255, 255, 255, 0.12) !important;
          color: #cbd5e1 !important;
        }
        .swagger-ui .btn.try-out__btn:hover {
          background: rgba(51, 65, 85, 0.85) !important;
          color: #ffffff !important;
          border-color: rgba(56, 189, 248, 0.4) !important;
        }
        .swagger-ui .btn.try-out__btn.cancel {
          background: rgba(244, 63, 94, 0.15) !important;
          border: 1px solid rgba(244, 63, 94, 0.4) !important;
          color: #fb7185 !important;
        }
        .swagger-ui .btn.execute {
          background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%) !important;
          border: 1px solid rgba(56, 189, 248, 0.5) !important;
          box-shadow: 0 0 16px rgba(14, 165, 233, 0.35) !important;
          color: #ffffff !important;
        }
        .swagger-ui .btn.execute:hover {
          background: linear-gradient(135deg, #0369a1 0%, #0284c7 100%) !important;
          box-shadow: 0 0 24px rgba(14, 165, 233, 0.55) !important;
          border-color: #38bdf8 !important;
          transform: translateY(-1px) !important;
        }
        .swagger-ui .btn.cancel {
          background: rgba(30, 41, 59, 0.6) !important;
          border: 1px solid rgba(255, 255, 255, 0.1) !important;
          color: #cbd5e1 !important;
        }

        /* Responses & Code Boxes */
        .swagger-ui .responses-table {
          background: transparent !important;
        }
        .swagger-ui .response-col_status {
          font-family: 'JetBrains Mono', monospace !important;
          font-weight: 700 !important;
          color: #10b981 !important;
          font-size: 0.9rem !important;
        }
        .swagger-ui .response-col_description {
          color: #94a3b8 !important;
          font-size: 0.85rem !important;
        }
        .swagger-ui .highlight-code,
        .swagger-ui .microlight,
        .swagger-ui pre,
        .swagger-ui pre.example,
        .swagger-ui pre.microlight {
          background: #020617 !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          border-radius: 8px !important;
          color: #e2e8f0 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.82rem !important;
          line-height: 1.5 !important;
          padding: 14px 16px !important;
        }
        .swagger-ui .highlight-code pre {
          background: transparent !important;
          border: none !important;
          padding: 0 !important;
        }
        .swagger-ui code {
          background: rgba(15, 23, 42, 0.8) !important;
          color: #38bdf8 !important;
          padding: 2px 6px !important;
          border-radius: 4px !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.82rem !important;
        }

        /* Tabs inside responses */
        .swagger-ui .tabli {
          border-bottom: 2px solid transparent !important;
        }
        .swagger-ui .tabli.active {
          border-bottom: 2px solid #38bdf8 !important;
        }
        .swagger-ui .tabli button {
          color: #94a3b8 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.78rem !important;
          font-weight: 600 !important;
        }
        .swagger-ui .tabli.active button {
          color: #38bdf8 !important;
        }

        /* Models & Schemas */
        .swagger-ui section.models {
          background: rgba(15, 23, 42, 0.6) !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          border-radius: 10px !important;
          margin-top: 32px !important;
          padding: 16px 20px !important;
        }
        .swagger-ui section.models.is-open h4 {
          border-bottom: 1px solid rgba(255, 255, 255, 0.06) !important;
          padding-bottom: 12px !important;
          color: #f1f5f9 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 1rem !important;
        }
        .swagger-ui section.models h4 {
          color: #f1f5f9 !important;
          font-family: 'JetBrains Mono', monospace !important;
        }
        .swagger-ui .model-box {
          background: rgba(2, 6, 23, 0.6) !important;
          border: 1px solid rgba(255, 255, 255, 0.06) !important;
          border-radius: 8px !important;
          padding: 12px 16px !important;
        }
        .swagger-ui .model-title {
          color: #38bdf8 !important;
          font-family: 'JetBrains Mono', monospace !important;
          font-size: 0.9rem !important;
        }
        .swagger-ui .model {
          color: #cbd5e1 !important;
          font-family: 'JetBrains Mono', monospace !important;
        }
        .swagger-ui .prop-name {
          color: #f1f5f9 !important;
        }
        .swagger-ui .prop-type {
          color: #a855f7 !important;
        }
        .swagger-ui .prop-format {
          color: #64748b !important;
        }
        .swagger-ui .model-toggle {
          filter: invert(1);
        }
      </style>
    </head>
    <body>
      <div class="swagger-ui">
        <div class="wrapper" style="padding-bottom: 0 !important;">
          <div class="api-nav-header">
            <div class="api-nav-brand">
              <span>THREAT<span class="highlight">TRACE</span></span>
              <span style="color: #64748b; font-size: 0.8rem; font-weight: 400;">// API SPECIFICATION</span>
            </div>
            <a href="/view-graph" class="api-nav-link">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
              Attribution Graph View &rarr;
            </a>
          </div>
        </div>
      </div>
      <div id="swagger-ui"></div>
      <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
      <script>
        SwaggerUIBundle({ url: '/openapi.json', dom_id: '#swagger-ui' });
      </script>
    </body>
    </html>
    """)

@app.post(
    "/attribute",
    summary="Ingest & Attribute Forensic Artifact",
    description="Ingest an email forensic artifact, evaluate Section 7 infrastructure relationship similarity scores against active threat telemetry, and dynamically cluster into coordinated syndicates.",
    tags=["Attribution Engine"]
)
def ingest_and_attribute(artifact: EmailForensicArtifact):
    graph_module.threat_engine.ingest_artifact(artifact.model_dump())
    return graph_module.threat_engine.analyze_campaigns()

@app.get(
    "/graph-data",
    summary="Fetch Attribution Graph",
    description="Retrieve the comprehensive multi-signal campaign graph, total entity metrics, active syndicates, and vis-network rendering payload.",
    tags=["Attribution Engine"]
)
def fetch_graph():
    return graph_module.threat_engine.analyze_campaigns()

@app.post(
    "/reset-graph",
    summary="Reset Attribution Graph",
    description="Reinitialize the attribution engine graph to default seeded demo syndicates (Microsoft/Azure Spoofing & Payroll Phishing).",
    tags=["Attribution Engine"]
)
def reset_graph():
    reset_default_nodes()
    return {"status": "reset complete"}

@app.get("/view-graph", response_class=HTMLResponse)
def view_graph():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ThreatTrace // Infrastructure Attribution Engine</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
      <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style>
        *, *::before, *::after {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }
        :root {
          --bg-base: #0b0f19;
          --bg-surface: rgba(15, 23, 42, 0.82);
          --border-subtle: rgba(255, 255, 255, 0.08);
          --border-highlight: rgba(56, 189, 248, 0.25);
          --crimson: #f43f5e;
          --cyan: #0ea5e9;
          --cyan-glow: #38bdf8;
          --purple: #8b5cf6;
          --text-primary: #f8fafc;
          --text-secondary: #94a3b8;
          --text-muted: #64748b;
        }
        body {
          background-color: var(--bg-base);
          color: var(--text-primary);
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
          height: 100vh;
          overflow: hidden;
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
        }

        /* Topbar Header */
        #topbar {
          height: 62px;
          background: var(--bg-surface);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border-bottom: 1px solid var(--border-subtle);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 24px;
          position: relative;
          z-index: 10;
        }
        .brand-section {
          display: flex;
          align-items: center;
          gap: 14px;
        }
        .brand-logo {
          width: 32px;
          height: 32px;
          border-radius: 8px;
          background: linear-gradient(135deg, rgba(14, 165, 233, 0.25), rgba(139, 92, 246, 0.3));
          border: 1px solid rgba(56, 189, 248, 0.4);
          box-shadow: 0 0 14px rgba(56, 189, 248, 0.25);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #38bdf8;
        }
        .brand-logo svg {
          width: 18px;
          height: 18px;
        }
        .brand-text {
          display: flex;
          flex-direction: column;
        }
        .brand-title {
          font-family: 'JetBrains Mono', monospace;
          font-weight: 800;
          font-size: 1.05rem;
          letter-spacing: 2px;
          color: #f8fafc;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .brand-title span.highlight {
          color: var(--cyan-glow);
          text-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
        }
        .brand-sub {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.68rem;
          color: var(--text-muted);
          letter-spacing: 1px;
          text-transform: uppercase;
        }

        .header-meta {
          display: flex;
          align-items: center;
          gap: 16px;
        }
        .telemetry-chip {
          display: flex;
          align-items: center;
          gap: 8px;
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 6px;
          padding: 5px 12px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.72rem;
          color: var(--text-secondary);
        }
        .telemetry-chip .live-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #10b981;
          box-shadow: 0 0 8px #10b981;
          animation: pulse-dot 2s infinite;
        }
        .status-pill {
          background: rgba(244, 63, 94, 0.12);
          color: #fb7185;
          border: 1px solid rgba(244, 63, 94, 0.45);
          box-shadow: 0 0 16px rgba(244, 63, 94, 0.2);
          padding: 6px 14px;
          border-radius: 9999px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.72rem;
          font-weight: 700;
          letter-spacing: 0.8px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .status-pill::before {
          content: '';
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #f43f5e;
          box-shadow: 0 0 8px #f43f5e;
          animation: pulse-crimson 1.5s infinite;
        }

        @keyframes pulse-dot {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.85); }
        }
        @keyframes pulse-crimson {
          0%, 100% { opacity: 1; box-shadow: 0 0 10px #f43f5e; }
          50% { opacity: 0.35; box-shadow: 0 0 2px #f43f5e; }
        }

        /* Viewport & Canvas Layout */
        #viewport {
          display: flex;
          height: calc(100vh - 62px);
          position: relative;
          overflow: hidden;
        }

        #network-canvas {
          flex: 1;
          height: 100%;
          background-color: #0b0f19;
          background-image: 
            radial-gradient(circle at center, rgba(56, 189, 248, 0.14) 1px, transparent 1px),
            linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
          background-size: 32px 32px, 32px 32px, 32px 32px;
          background-position: 0 0, 0 0, 0 0;
          position: relative;
          outline: none;
        }

        /* Ambient subtle vignette over canvas */
        .canvas-overlay-vignette {
          position: absolute;
          inset: 0;
          background: radial-gradient(ellipse at center, transparent 40%, rgba(11, 15, 25, 0.65) 100%);
          pointer-events: none;
          z-index: 1;
        }

        /* Canvas HUD Watermark / Control overlay */
        .hud-telemetry {
          position: absolute;
          top: 16px;
          left: 20px;
          z-index: 5;
          pointer-events: none;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.68rem;
          color: rgba(148, 163, 184, 0.65);
          background: rgba(15, 23, 42, 0.75);
          backdrop-filter: blur(10px);
          -webkit-backdrop-filter: blur(10px);
          border: 1px solid rgba(255, 255, 255, 0.07);
          border-radius: 6px;
          padding: 5px 12px;
          letter-spacing: 1px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .canvas-controls {
          position: absolute;
          bottom: 20px;
          left: 20px;
          z-index: 5;
          display: flex;
          gap: 6px;
          pointer-events: auto;
        }
        .hud-btn {
          width: 32px;
          height: 32px;
          border-radius: 6px;
          background: rgba(15, 23, 42, 0.75);
          border: 1px solid rgba(255, 255, 255, 0.08);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          color: var(--text-secondary);
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 0.85rem;
          cursor: pointer;
          transition: all 0.2s;
        }
        .hud-btn:hover {
          background: rgba(30, 41, 59, 0.9);
          border-color: rgba(56, 189, 248, 0.4);
          color: var(--cyan-glow);
          box-shadow: 0 0 10px rgba(56, 189, 248, 0.2);
        }

        /* Sidebar Styling (Palantir/Maltego High-Tier Intelligence) */
        #sidebar {
          width: 340px;
          background: var(--bg-surface);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border-left: 1px solid var(--border-subtle);
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 12px;
          overflow-y: auto;
          position: relative;
          z-index: 10;
          box-shadow: -8px 0 32px rgba(0, 0, 0, 0.4);
        }
        #sidebar::-webkit-scrollbar {
          width: 5px;
        }
        #sidebar::-webkit-scrollbar-track {
          background: transparent;
        }
        #sidebar::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.1);
          border-radius: 10px;
        }

        .panel-box {
          background: rgba(30, 41, 59, 0.35);
          border: 1px solid rgba(255, 255, 255, 0.06);
          padding: 13px;
          border-radius: 10px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
          transition: border-color 0.2s;
          position: relative;
        }
        .panel-box:hover {
          border-color: var(--border-highlight);
        }
        .panel-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.72rem;
          text-transform: uppercase;
          letter-spacing: 1.5px;
          color: var(--text-secondary);
          margin-bottom: 12px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .panel-title::before {
          content: '◆';
          font-size: 0.6rem;
          color: var(--cyan-glow);
        }

        /* Forensic Indicators Stat Cards */
        .stat-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }
        .stat-card {
          background: rgba(15, 23, 42, 0.7);
          padding: 12px 14px;
          border-radius: 8px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          position: relative;
          overflow: hidden;
        }
        .stat-card.nodes-card {
          border-top: 2px solid #38bdf8;
        }
        .stat-card.gangs-card {
          border-top: 2px solid #f43f5e;
        }
        .stat-num {
          font-family: 'JetBrains Mono', monospace;
          font-size: 1.7rem;
          font-weight: 700;
          line-height: 1.1;
        }
        .nodes-card .stat-num {
          color: #38bdf8;
          text-shadow: 0 0 14px rgba(56, 189, 248, 0.4);
        }
        .gangs-card .stat-num {
          color: #f43f5e;
          text-shadow: 0 0 14px rgba(244, 63, 94, 0.4);
        }
        .stat-label {
          font-size: 0.7rem;
          color: var(--text-secondary);
          font-weight: 500;
          text-transform: uppercase;
          letter-spacing: 0.6px;
          margin-top: 5px;
        }

        /* Entity Key Legend */
        .legend-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .legend-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 8px 10px;
          background: rgba(15, 23, 42, 0.5);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-radius: 6px;
          font-size: 0.8rem;
          color: #cbd5e1;
        }
        .legend-left {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .legend-shape {
          width: 16px;
          height: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        }
        .shape-pill {
          width: 16px;
          height: 9px;
          border-radius: 4px;
          background: rgba(244, 63, 94, 0.2);
          border: 1.5px solid #f43f5e;
          box-shadow: 0 0 8px rgba(244, 63, 94, 0.5);
        }
        .shape-ellipse {
          width: 15px;
          height: 11px;
          border-radius: 50%;
          background: rgba(14, 165, 233, 0.2);
          border: 1.5px solid #0ea5e9;
          box-shadow: 0 0 8px rgba(14, 165, 233, 0.5);
        }
        .shape-hex {
          width: 13px;
          height: 13px;
          background: rgba(139, 92, 246, 0.25);
          border: 1.5px solid #8b5cf6;
          clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
          box-shadow: 0 0 8px rgba(139, 92, 246, 0.6);
        }
        .legend-badge {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.65rem;
          padding: 2px 6px;
          border-radius: 4px;
          background: rgba(255, 255, 255, 0.04);
          color: var(--text-muted);
          letter-spacing: 0.5px;
        }

        /* Inspector Details Box */
        #inspector-box {
          display: none;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.72rem;
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid rgba(56, 189, 248, 0.3);
          border-radius: 8px;
          padding: 12px;
          margin-top: -6px;
        }
        #inspector-box .prop-row {
          display: flex;
          justify-content: space-between;
          padding: 4px 0;
          border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        #inspector-box .prop-row:last-child {
          border-bottom: none;
        }
        #inspector-box .prop-name {
          color: var(--text-muted);
        }
        #inspector-box .prop-val {
          color: var(--cyan-glow);
          word-break: break-all;
          max-width: 170px;
          text-align: right;
        }

        /* Action Buttons */
        .btn-inject {
          background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
          color: #ffffff;
          border: 1px solid rgba(56, 189, 248, 0.5);
          box-shadow: 0 0 18px rgba(14, 165, 233, 0.35);
          border-radius: 8px;
          padding: 12px 14px;
          font-family: 'Inter', sans-serif;
          font-weight: 600;
          font-size: 0.84rem;
          letter-spacing: 0.3px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .btn-inject:hover {
          background: linear-gradient(135deg, #0369a1 0%, #0284c7 100%);
          box-shadow: 0 0 26px rgba(14, 165, 233, 0.55);
          border-color: #38bdf8;
          transform: translateY(-1px);
        }
        .btn-inject:active {
          transform: translateY(0);
        }
        .btn-reset {
          background: rgba(30, 41, 59, 0.6);
          color: #cbd5e1;
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          padding: 10px 14px;
          font-family: 'Inter', sans-serif;
          font-weight: 600;
          font-size: 0.8rem;
          letter-spacing: 0.2px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          transition: all 0.2s;
        }
        .btn-reset:hover {
          background: rgba(51, 65, 85, 0.8);
          color: #ffffff;
          border-color: rgba(255, 255, 255, 0.2);
        }
        .btn-reset:active {
          transform: translateY(0);
        }
      </style>
    </head>
    <body>
      <div id="topbar">
        <div class="brand-section">
          <div class="brand-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
              <polyline points="2 17 12 22 22 17"></polyline>
              <polyline points="2 12 12 17 22 12"></polyline>
            </svg>
          </div>
          <div class="brand-text">
            <div class="brand-title">THREAT<span class="highlight">TRACE</span></div>
            <div class="brand-sub">Infrastructure Attribution Engine</div>
          </div>
        </div>

        <div class="header-meta">
          <div class="telemetry-chip">
            <div class="live-dot"></div>
            <span>LIVE CORRELATION</span>
          </div>
          <div class="status-pill">COORDINATED SYNDICATE DETECTED</div>
        </div>
      </div>

      <div id="viewport">
        <div id="network-container" style="flex: 1; height: 100%; position: relative; overflow: hidden;">
          <div id="network-canvas" style="width: 100%; height: 100%;"></div>
          <div class="canvas-overlay-vignette"></div>
          <div class="hud-telemetry">
            <span>GRID: 32PX</span>
            <span>•</span>
            <span>FORCEATLAS2</span>
            <span>•</span>
            <span id="hud-entity-count">ACTIVE</span>
          </div>
          <div class="canvas-controls">
            <button class="hud-btn" onclick="network && network.moveTo({ scale: network.getScale() * 1.25 })" title="Zoom In">+</button>
            <button class="hud-btn" onclick="network && network.moveTo({ scale: network.getScale() * 0.8 })" title="Zoom Out">−</button>
            <button class="hud-btn" onclick="network && network.fit({ animation: { duration: 600, easingFunction: 'easeInOutQuad' } })" title="Fit Constellation">⤢</button>
          </div>
        </div>

        <div id="sidebar">
          <div class="panel-box">
            <div class="panel-title">Forensic Indicators</div>
            <div class="stat-grid">
              <div class="stat-card nodes-card">
                <div class="stat-num" id="stat-nodes">0</div>
                <div class="stat-label">Nodes Traced</div>
              </div>
              <div class="stat-card gangs-card">
                <div class="stat-num" id="stat-campaigns">0</div>
                <div class="stat-label">Active Gangs</div>
              </div>
            </div>
          </div>

          <div class="panel-box">
            <div class="panel-title">Entity Key</div>
            <div class="legend-list">
              <div class="legend-item">
                <div class="legend-left">
                  <div class="legend-shape"><div class="shape-pill"></div></div>
                  <span>Sender Personas</span>
                </div>
                <span class="legend-badge">ATTACKER</span>
              </div>
              <div class="legend-item">
                <div class="legend-left">
                  <div class="legend-shape"><div class="shape-ellipse"></div></div>
                  <span>Spoofed Domains</span>
                </div>
                <span class="legend-badge">HOST</span>
              </div>
              <div class="legend-item">
                <div class="legend-left">
                  <div class="legend-shape"><div class="shape-hex"></div></div>
                  <span>Infrastructure IPs</span>
                </div>
                <span class="legend-badge">ROOT GANG</span>
              </div>
            </div>
          </div>

          <div class="panel-box" id="panel-inspector" style="display:none;">
            <div class="panel-title" id="insp-header">Telemetry</div>
            <div id="inspector-box" style="display:block;">
              <div class="prop-row"><span class="prop-name" id="insp-k1">LABEL</span><span class="prop-val" id="insp-label">-</span></div>
              <div class="prop-row"><span class="prop-name" id="insp-k2">TYPE</span><span class="prop-val" id="insp-type">-</span></div>
              <div class="prop-row"><span class="prop-name" id="insp-k3">DEGREE</span><span class="prop-val" id="insp-degree">-</span></div>
              <div class="prop-row" id="insp-row-score" style="display:none;"><span class="prop-name">SCORE</span><span class="prop-val" id="insp-score">-</span></div>
              <div class="prop-row" id="insp-row-signals" style="display:none;"><span class="prop-name">SIGNALS</span><span class="prop-val" id="insp-signals">-</span></div>
            </div>
          </div>

          <div class="panel-box" style="display:flex; flex-direction:column; gap:10px; margin-top:auto;">
            <div class="panel-title">Tactical Actions</div>
            <button class="btn-inject" onclick="simulateIncomingAttack()">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
              Ingest Correlated Attack
            </button>
            <button class="btn-reset" onclick="resetGraph()">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><polyline points="3 3 3 8 8 8"></polyline></svg>
              Reset Graph
            </button>
          </div>
        </div>
      </div>

      <script>
        let network = null;

        function refreshGraph() {
          fetch('/graph-data')
            .then(res => res.json())
            .then(data => {
              document.getElementById('stat-nodes').innerText = data.summary.total_entities;
              document.getElementById('stat-campaigns').innerText = data.summary.identified_campaigns;

              const hudCount = document.getElementById('hud-entity-count');
              if (hudCount) {
                hudCount.innerText = data.summary.total_entities + ' NODES / ' + data.summary.total_relationships + ' LINKS';
              }

              const container = document.getElementById('network-canvas');

              // Map nodes according to high-tier cyber intelligence specifications
              const nodes = new vis.DataSet(data.vis_graph.nodes.map(n => {
                if (n.type === 'sender') {
                  // Senders (Attacker personas): Sleek rounded pills with crimson accent (#f43f5e), compact widthConstraint
                  return {
                    id: n.id,
                    label: n.label,
                    title: `${n.label}\n[ATTACKER PERSONA]\nFraud Risk: ${n.fraud_score !== undefined ? n.fraud_score : '0.90+'}`,
                    rawType: n.type,
                    shape: 'box',
                    shapeProperties: {
                      borderRadius: 6
                    },
                    widthConstraint: { maximum: 160 },
                    color: {
                      background: 'rgba(244, 63, 94, 0.14)',
                      border: '#f43f5e',
                      highlight: {
                        background: 'rgba(244, 63, 94, 0.32)',
                        border: '#fb7185'
                      },
                      hover: {
                        background: 'rgba(244, 63, 94, 0.24)',
                        border: '#fda4af'
                      }
                    },
                    borderWidth: 1.5,
                    borderWidthSelected: 2.5,
                    margin: { top: 8, right: 12, bottom: 8, left: 12 },
                    shadow: {
                      enabled: true,
                      color: 'rgba(244, 63, 94, 0.45)',
                      size: 10,
                      x: 0,
                      y: 0
                    },
                    font: {
                      color: '#ffffff',
                      face: 'JetBrains Mono',
                      size: 11,
                      strokeWidth: 2,
                      strokeColor: '#0b0f19',
                      minVisible: 3,
                      multi: true
                    }
                  };
                } else if (n.type === 'domain') {
                  // Domains (Spoofed hosts): Ellipses with cyan accents (#0ea5e9), semi-translucent fill, compact widthConstraint
                  const ageTxt = (n.domain_age_days !== undefined && n.domain_age_days !== null) ? `${n.domain_age_days}d old` : 'Domain Host';
                  return {
                    id: n.id,
                    label: n.label,
                    title: `${n.label}\n[SPOOFED DOMAIN]\nAge: ${ageTxt}`,
                    rawType: n.type,
                    shape: 'ellipse',
                    widthConstraint: { maximum: 150 },
                    color: {
                      background: 'rgba(14, 165, 233, 0.14)',
                      border: '#0ea5e9',
                      highlight: {
                        background: 'rgba(14, 165, 233, 0.32)',
                        border: '#38bdf8'
                      },
                      hover: {
                        background: 'rgba(14, 165, 233, 0.24)',
                        border: '#7dd3fc'
                      }
                    },
                    borderWidth: 1.5,
                    borderWidthSelected: 2.5,
                    margin: { top: 9, right: 14, bottom: 9, left: 14 },
                    shadow: {
                      enabled: true,
                      color: 'rgba(14, 165, 233, 0.45)',
                      size: 10,
                      x: 0,
                      y: 0
                    },
                    font: {
                      color: '#f0f9ff',
                      face: 'Inter',
                      size: 11.5,
                      strokeWidth: 2,
                      strokeColor: '#0b0f19',
                      minVisible: 3,
                      multi: true
                    }
                  };
                } else {
                  // Infrastructure IPs (The root gang anchors): Large hexagons with vibrant purple glow (#8b5cf6)
                  const locTxt = n.location && n.location.country ? `${n.location.city || ''}, ${n.location.country} (${n.location.isp || ''})` : 'Infrastructure Anchor';
                  return {
                    id: n.id,
                    label: n.label,
                    title: `${n.label}\n[INFRASTRUCTURE IP]\nLocation: ${locTxt}`,
                    rawType: n.type,
                    shape: 'hexagon',
                    size: 32,
                    widthConstraint: { maximum: 140 },
                    color: {
                      background: 'rgba(139, 92, 246, 0.24)',
                      border: '#8b5cf6',
                      highlight: {
                        background: 'rgba(139, 92, 246, 0.45)',
                        border: '#c4b5fd'
                      },
                      hover: {
                        background: 'rgba(139, 92, 246, 0.35)',
                        border: '#a78bfa'
                      }
                    },
                    borderWidth: 2,
                    borderWidthSelected: 3,
                    margin: 10,
                    shadow: {
                      enabled: true,
                      color: 'rgba(139, 92, 246, 0.65)',
                      size: 14,
                      x: 0,
                      y: 0
                    },
                    font: {
                      color: '#ffffff',
                      face: 'JetBrains Mono',
                      size: 12,
                      bold: true,
                      strokeWidth: 2.5,
                      strokeColor: '#0b0f19',
                      minVisible: 3,
                      multi: true
                    }
                  };
                }
              }));

              // Edges & Connections: clean vectors, NO long static labels, tooltip on hover
              const edges = new vis.DataSet(data.vis_graph.edges.map(e => {
                const isCorr = e.edge_type === 'correlation' || (e.relation && e.relation.startsWith('CORRELATION_SCORE'));
                
                // Clean hover tooltip
                let hoverTooltip = '';
                if (isCorr) {
                  const scoreVal = (e.score !== undefined && e.score !== null) ? e.score : (e.correlation_score || 75);
                  const reasonsList = (e.reasons && e.reasons.length) ? e.reasons.join(' & ') : 'Shared IP & Auth Failure';
                  hoverTooltip = `Correlation Score: ${scoreVal} | ${reasonsList}`;
                } else {
                  hoverTooltip = e.title || e.relation || 'Infrastructure Link';
                }

                // Visible label: ultra-short (just numeric score "75" for correlation, empty for structural hops)
                const shortLabel = isCorr && (e.score || e.correlation_score) ? String(e.score || e.correlation_score) : '';

                return {
                  id: e.source + '___' + e.target + '___' + (e.relation || ''),
                  from: e.source,
                  to: e.target,
                  label: shortLabel,
                  title: hoverTooltip,
                  rawEdge: e,
                  color: isCorr ? {
                    color: 'rgba(244, 63, 94, 0.55)',
                    highlight: '#f43f5e',
                    hover: '#fb7185'
                  } : {
                    color: 'rgba(148, 163, 184, 0.28)',
                    highlight: '#38bdf8',
                    hover: '#38bdf8'
                  },
                  width: isCorr ? 2.0 : 1.2,
                  selectionWidth: isCorr ? 3.0 : 2.0,
                  hoverWidth: isCorr ? 2.6 : 1.8,
                  dashes: isCorr ? true : false,
                  arrows: {
                    to: {
                      enabled: !isCorr,
                      scaleFactor: 0.6,
                      type: 'arrow'
                    }
                  },
                  smooth: {
                    type: 'curvedCW',
                    roundness: isCorr ? 0.25 : 0.18
                  },
                  font: {
                    color: '#fda4af',
                    size: 9.5,
                    face: 'JetBrains Mono',
                    align: 'middle',
                    background: isCorr ? 'rgba(15, 23, 42, 0.85)' : 'transparent',
                    strokeWidth: 0,
                    minVisible: 4
                  }
                };
              }));

              // Physics & Spacing: forceAtlas2Based with ample breathing room
              const options = {
                physics: {
                  solver: 'forceAtlas2Based',
                  forceAtlas2Based: {
                    gravitationalConstant: -120,
                    centralGravity: 0.008,
                    springLength: 240,
                    springConstant: 0.04,
                    damping: 0.5,
                    avoidOverlap: 1.0
                  },
                  maxVelocity: 40,
                  minVelocity: 0.75,
                  stabilization: {
                    enabled: true,
                    iterations: 250,
                    updateInterval: 25,
                    fit: true
                  }
                },
                interaction: {
                  hover: true,
                  tooltipDelay: 60,
                  hideEdgesOnDrag: false,
                  zoomView: true,
                  dragView: true
                },
                layout: {
                  improvedLayout: true
                }
              };

              if (!network) {
                network = new vis.Network(container, { nodes, edges }, options);

                network.on('selectNode', function(params) {
                  if (params.nodes.length > 0) {
                    const nodeId = params.nodes[0];
                    const nodeObj = nodes.get(nodeId);
                    const connectedEdges = network.getConnectedEdges(nodeId);
                    
                    const inspBox = document.getElementById('panel-inspector');
                    if (inspBox && nodeObj) {
                      inspBox.style.display = 'block';
                      document.getElementById('insp-header').innerText = 'Node Telemetry';
                      document.getElementById('insp-k1').innerText = 'LABEL';
                      document.getElementById('insp-label').innerText = nodeObj.label || nodeId;
                      document.getElementById('insp-k2').innerText = 'TYPE';
                      document.getElementById('insp-type').innerText = (nodeObj.rawType || 'ENTITY').toUpperCase();
                      document.getElementById('insp-k3').innerText = 'DEGREE';
                      document.getElementById('insp-degree').innerText = connectedEdges.length + ' links';

                      const scoreRow = document.getElementById('insp-row-score');
                      const signalsRow = document.getElementById('insp-row-signals');
                      if (scoreRow) scoreRow.style.display = 'none';
                      if (signalsRow) signalsRow.style.display = 'none';
                    }
                  }
                });

                network.on('selectEdge', function(params) {
                  if (params.nodes.length === 0 && params.edges.length > 0) {
                    const edgeId = params.edges[0];
                    const edgeObj = edges.get(edgeId);
                    const inspBox = document.getElementById('panel-inspector');
                    if (inspBox && edgeObj) {
                      inspBox.style.display = 'block';
                      const raw = edgeObj.rawEdge || {};
                      const isCorr = raw.edge_type === 'correlation' || (raw.relation && raw.relation.startsWith('CORRELATION_SCORE'));
                      document.getElementById('insp-header').innerText = isCorr ? 'Syndicate Link Telemetry' : 'Infrastructure Link';
                      document.getElementById('insp-k1').innerText = 'RELATION';
                      document.getElementById('insp-label').innerText = raw.relation || edgeObj.title || 'CONNECTED';
                      document.getElementById('insp-k2').innerText = 'LINK TYPE';
                      document.getElementById('insp-type').innerText = isCorr ? 'MULTI-SIGNAL CORRELATION' : 'STRUCTURAL HOP';
                      document.getElementById('insp-k3').innerText = 'NODES';
                      document.getElementById('insp-degree').innerText = edgeObj.from + ' ➔ ' + edgeObj.to;
                      
                      const scoreRow = document.getElementById('insp-row-score');
                      const signalsRow = document.getElementById('insp-row-signals');
                      if (isCorr) {
                        if (scoreRow) {
                          scoreRow.style.display = 'flex';
                          const scoreVal = (raw.score !== undefined && raw.score !== null) ? raw.score : (raw.correlation_score || '75');
                          document.getElementById('insp-score').innerText = scoreVal + ' / 100 (>= 60 THRESHOLD MET)';
                        }
                        if (signalsRow) {
                          signalsRow.style.display = 'flex';
                          const sigs = (raw.reasons && raw.reasons.length) ? raw.reasons.join(' & ') : 'Shared IP & Auth Failure';
                          document.getElementById('insp-signals').innerText = sigs;
                        }
                      } else {
                        if (scoreRow) scoreRow.style.display = 'none';
                        if (signalsRow) signalsRow.style.display = 'none';
                      }
                    }
                  }
                });

                network.on('deselectNode', function() {
                  const inspBox = document.getElementById('panel-inspector');
                  if (inspBox) inspBox.style.display = 'none';
                });

                network.on('deselectEdge', function() {
                  const inspBox = document.getElementById('panel-inspector');
                  if (inspBox) inspBox.style.display = 'none';
                });
              } else {
                network.setData({ nodes, edges });
              }
            });
        }

        function simulateIncomingAttack() {
          const randomId = Math.floor(100 + Math.random() * 900);
          fetch('/attribute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email_id: 'MSG-' + randomId,
              sender: 'urgent-transfer' + randomId + '@secure-banking-notice.com',
              domain: 'secure-banking-notice.com',
              origin_ip: '185.220.101.5',
              location: { country: 'NL', city: 'Amsterdam', isp: 'HostPalace Web Services' },
              spf_status: 'FAIL',
              dkim_status: 'FAIL',
              dmarc_status: 'FAIL',
              domain_age_days: 6,
              urls: ['https://secure-banking-notice.com/auth/verify?token=' + randomId],
              fraud_score: 0.95
            })
          }).then(() => refreshGraph());
        }

        function resetGraph() {
          fetch('/reset-graph', { method: 'POST' }).then(() => refreshGraph());
        }

        refreshGraph();
      </script>
    </body>
    </html>
    """