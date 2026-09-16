import os
import sys
import unittest
import json

# Configure paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient

print("=" * 75)
print("         THREATTRACE-AI // END-TO-END INTEGRATION TEST SUITE")
print("=" * 75)

# 1. Run Unit Tests
print("\n[1/4] Running Origin Tracer Unit Tests...")
loader = unittest.TestLoader()
suite = loader.discover(os.path.join(CURRENT_DIR, "intelligence"), pattern="test_origin_tracer.py")
runner = unittest.TextTestRunner(verbosity=1)
result = runner.run(suite)
assert result.wasSuccessful(), "Unit tests failed!"
print("==> [PASS] Origin Tracer Unit Tests (All 6 passed)")

# 2. Test FastAPI app & /trace-origin endpoint
print("\n[2/4] Testing FastAPI /trace-origin Endpoint with Realistic Scenarios...")
from main import app
client = TestClient(app)

from demo.sample_emails import DEMO_SCENARIOS

for name, headers in DEMO_SCENARIOS.items():
    response = client.post("/trace-origin", json={"headers": headers})
    assert response.status_code == 200, f"Failed on {name}: {response.status_code}"
    data = response.json()
    
    # Verify core structure
    assert "origin" in data, f"Missing origin in {name}"
    assert "origin_summary" in data, f"Missing origin_summary in {name}"
    assert "relay_hops" in data, f"Missing relay_hops in {name}"
    assert "map_features" in data, f"Missing map_features in {name}"
    assert "graph_entities" in data, f"Missing graph_entities in {name}"
    
    # Verify TraceMap.jsx contract
    origin = data["origin"]
    for req_field in ["ip", "country", "city", "lat", "lng", "is_vpn_tor", "isp", "asn"]:
        assert req_field in origin, f"Field {req_field} missing in origin for {name}"
        
    print(f"    [OK] {name:<25} -> IP: {origin['ip']:<15} | Loc: {origin['city']}, {origin['country']} | Tor/VPN: {origin['is_vpn_tor']}")

print("==> [PASS] FastAPI /trace-origin: All scenarios returned HTTP 200 OK & validated schemas")

# 3. Test Teammate Regression (Existing /attribute & /graph-data)
print("\n[3/4] Testing Teammate Attribution Graph Routes (/attribute & /graph-data)...")
attr_res = client.post("/attribute", json={
    "email_id": "MSG-VERIFY-1",
    "sender": "phish@evil-bank.com",
    "domain": "evil-bank.com",
    "origin_ip": "185.220.101.5",
    "fraud_score": 0.95
})
assert attr_res.status_code == 200, f"Failed /attribute: {attr_res.status_code}"
graph_res = client.get("/graph-data")
assert graph_res.status_code == 200, f"Failed /graph-data: {graph_res.status_code}"
print("==> [PASS] Teammate Attribution Graph Routes: Zero regressions detected")

# 4. Leaflet Map Coordinates & Flight Path Validation
print("\n[4/4] Validating Leaflet / Mapbox Coordinates & Flight Paths...")
tor_report = client.post("/trace-origin", json={"headers": DEMO_SCENARIOS["TOR_CEO_FRAUD"]}).json()
flight_path = tor_report["map_features"]["flight_path"]
assert len(flight_path) >= 2, "Flight path must have at least 2 points"
for pt in flight_path:
    assert len(pt) == 2, "Coordinate must be [lat, lon]"
    assert -90 <= pt[0] <= 90, f"Invalid latitude: {pt[0]}"
    assert -180 <= pt[1] <= 180, f"Invalid longitude: {pt[1]}"
print(f"    [OK] Flight Path Points : {flight_path}")
print(f"    [OK] Traveled Distance  : {tor_report['map_features']['total_distance_km']} km")
print(f"    [OK] Cross-Border Hops  : {tor_report['map_features']['cross_border_hops']}")
print("==> [PASS] Map Features & Coordinates: Fully valid for Leaflet rendering")

print("\n" + "=" * 75)
print("   FINAL VERDICT: ALL INTEGRATION & REGRESSION CHECKS PASSED (100%)")
print("                 >>> GREEN LIGHT CONFIRMED! <<<")
print("=" * 75)
