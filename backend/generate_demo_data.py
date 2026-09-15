import json
from backend.intelligence.attribution_graph import ThreatGraphEngine

def build_demo_dataset():
    engine = ThreatGraphEngine()

    # 4 sample phishing emails simulating a real attack syndicate
    samples = [
        {"email_id": "MSG-001", "sender": "support@micros0ft-verify.com", "origin_ip": "185.220.101.5", "domain": "micros0ft-verify.com", "threat_score": 0.91},
        {"email_id": "MSG-002", "sender": "security@office-renew.net", "origin_ip": "185.220.101.5", "domain": "office-renew.net", "threat_score": 0.94},
        {"email_id": "MSG-003", "sender": "admin@hr-portal-login.org", "origin_ip": "194.26.29.112", "domain": "hr-portal-login.org", "threat_score": 0.88},
        {"email_id": "MSG-004", "sender": "payroll@hr-portal-login.org", "origin_ip": "194.26.29.112", "domain": "hr-portal-login.org", "threat_score": 0.96},
    ]

    for item in samples:
        engine.ingest_email_event(
            sender=item["sender"],
            ip=item["origin_ip"],
            domain=item["domain"],
            email_id=item["email_id"],
            threat_score=item["threat_score"]
        )

    output = engine.analyze_campaigns()

    with open("backend/demo_attribution_data.json", "w") as f:
        json.dump(output, f, indent=2)

    print("Success: backend/demo_attribution_data.json has been generated.")

if __name__ == "__main__":
    build_demo_dataset()
    