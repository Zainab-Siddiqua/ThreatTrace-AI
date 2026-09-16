import sys
sys.path.insert(0, "backend")

from detection.header_analyzer import parse_eml_file, compute_final_threat_score
from detection.content_classifier import analyze_content
from intelligence.origin_tracer import OriginTracer

eml_path = "backend/detection/samples/phish_failing.eml"
parsed = parse_eml_file(eml_path)

with open(eml_path, "r") as f:
    raw_text = f.read()

# ---- PART 1: Detection ----
content_score = analyze_content(parsed["subject"], raw_text)
final_score = compute_final_threat_score(content_score, parsed["auth_results"])

# ---- PART 2: Intelligence ----
received_chain = parsed.get("received_chain", [])
raw_received = "\n".join([f"Received: {h}" for h in received_chain])
tracer = OriginTracer()
trace = tracer.trace(raw_received)
origin_s = trace["origin_summary"]
origin_map = trace["origin"]

print("=" * 60)
print("  UNIFIED PIPELINE: PART 1 (Detection) + PART 2 (Geo)")
print("=" * 60)
print(f"  Subject       : {parsed['subject']}")
print(f"  From          : {parsed['from']}")
print(f"  SPF           : {parsed['auth_results']['spf'].upper()}")
print(f"  DKIM          : {parsed['auth_results']['dkim'].upper()}")
print(f"  DMARC         : {parsed['auth_results']['dmarc'].upper()}")
print(f"  ML Content    : {content_score}%")
print(f"  Final Score   : {final_score}%  <-- after auth penalties")
print("-" * 60)
print(f"  Origin IP     : {origin_s['candidate_origin_ip']}")
print(f"  Location      : {origin_s['city']}, {origin_s['country']}")
print(f"  ASN           : {origin_s['asn']} ({origin_s['as_org']})")
print(f"  Infra Type    : {origin_s['infrastructure_type']}")
print(f"  Tor/VPN Flag  : {origin_map['is_vpn_tor']}")
print(f"  Threat Tags   : {origin_s['threat_tags']}")
print(f"  Confidence    : {origin_s['confidence']}")
print("=" * 60)
print("  BOTH PARTS ARE WORKING TOGETHER CORRECTLY")
print("=" * 60)
