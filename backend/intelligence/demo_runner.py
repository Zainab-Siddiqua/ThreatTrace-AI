"""
Demo Runner for Geospatial & Origin-Tracing Intelligence Engine.
Executes deep forensic origin tracing on 4 distinct scenarios and displays results.
"""

import os
import sys
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, BACKEND_DIR)

from intelligence.origin_tracer import OriginTracer
from demo.sample_emails import DEMO_SCENARIOS


def main():
    tracer = OriginTracer()

    print("=" * 80)
    print("      SIH EMAIL FORENSIC PLATFORM - GEOSPATIAL & ORIGIN TRACING ENGINE")
    print("=" * 80)
    print()

    for name, raw_headers in DEMO_SCENARIOS.items():
        print("-" * 80)
        print(f"[*] ANALYZING SCENARIO: {name}")
        print("-" * 80)

        report = tracer.trace(raw_headers)
        origin = report.get("origin_summary")
        map_feats = report.get("map_features")

        if origin:
            print(f"  [+] Candidate Origin IP : {origin['candidate_origin_ip']}")
            print(f"  [+] Geographic Location : {origin['city'] or 'N/A'}, {origin['country']} ({origin['country_code']})")
            print(f"  [+] Coordinates         : {origin['coordinates']}")
            print(f"  [+] Autonomous System   : {origin['asn']} ({origin['as_org']})")
            print(f"  [+] Infra Category      : {origin['infrastructure_type']}")
            print(f"  [+] Suspicious Flag     : {'YES ??' if origin['is_suspicious_infra'] else 'NO (Normal)'}")
            print(f"  [+] Threat Tags         : {', '.join(origin['threat_tags']) or 'None'}")
            print(f"  [+] Forensic Confidence : {origin['confidence']}")
            print(f"\n  [Forensic Explanation]")
            print(f"  \"{origin['forensic_reasoning']}\"")
        else:
            print("  [-] No external origin identified.")

        print(f"\n  [Relay Path Progression - {len(report['relay_hops'])} Hops]")
        for hop in report["relay_hops"]:
            loc_str = f"{hop['location']['city'] or ''}, {hop['location']['country'] or 'Internal'}"
            asn_str = hop['network']['as_org'] or 'Private Network'
            flag_str = f" [{', '.join(hop['anomaly_flags'])}]" if hop['anomaly_flags'] else ""
            print(f"    Hop #{hop['hop_index']} ({hop['hop_type']:<18}): IP={hop['ip']:<15} | Location={loc_str:<25} | Org={asn_str[:22]:<22}{flag_str}")

        print(f"\n  [Map Features for Frontend (Leaflet / Mapbox)]")
        print(f"    Flight Path Coords : {map_feats['flight_path']}")
        print(f"    Total Traveled Dist: {map_feats['total_distance_km']} km")
        print(f"    Cross-Border Hops  : {map_feats['cross_border_hops']}")

        print(f"\n  [Graph Entities for Part 2 Correlation]")
        print(f"    {report['graph_entities']}")
        print()


if __name__ == "__main__":
    main()
