"""
Unit Tests for Origin-Tracing and Geospatial Intelligence Engine.
"""

import unittest
import os
import sys

# Ensure backend directory is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, BACKEND_DIR)

from intelligence.origin_tracer import OriginTracer, is_private_ip, get_subnet_24
from demo.sample_emails import (
    SCENARIO_1_BULLETPROOF_RELAY,
    SCENARIO_2_TOR_CEO_FRAUD,
    SCENARIO_3_AWS_COMPROMISED_VPS,
    SCENARIO_4_LEGITIMATE_M365
)


class TestOriginTracer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tracer = OriginTracer()

    def test_private_ip_classifier(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.5.20"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("185.220.101.5"))

    def test_subnet_generation(self):
        self.assertEqual(get_subnet_24("185.220.101.5"), "185.220.101.0/24")
        self.assertEqual(get_subnet_24("91.215.85.17"), "91.215.85.0/24")

    def test_scenario_1_bulletproof_relay(self):
        res = self.tracer.trace(SCENARIO_1_BULLETPROOF_RELAY)
        self.assertIsNotNone(res["origin_summary"])
        
        origin = res["origin_summary"]
        # Must ignore internal 192.168.10.55 and isolate public 91.215.85.17
        self.assertEqual(origin["candidate_origin_ip"], "91.215.85.17")
        self.assertEqual(origin["country_code"], "RU")
        self.assertIn("Russia", origin["country"])
        self.assertEqual(origin["confidence"], "HIGH")
        
        # Check relay hops count
        self.assertEqual(len(res["relay_hops"]), 3)
        self.assertEqual(res["relay_hops"][0]["ip"], "192.168.10.55")
        self.assertTrue(res["relay_hops"][0]["is_private"])
        
        # Check map flight path
        map_feats = res["map_features"]
        self.assertGreaterEqual(len(map_feats["flight_path"]), 2)
        self.assertGreater(map_feats["total_distance_km"], 500)

    def test_scenario_2_tor_ceo_fraud(self):
        res = self.tracer.trace(SCENARIO_2_TOR_CEO_FRAUD)
        origin = res["origin_summary"]
        self.assertEqual(origin["candidate_origin_ip"], "185.220.101.5")
        self.assertEqual(origin["country_code"], "DE")
        self.assertTrue(origin["is_suspicious_infra"])
        self.assertIn("TOR_EXIT_NODE", origin["threat_tags"])
        self.assertEqual(origin["infrastructure_type"], "Tor / Anonymizing Proxy")

    def test_scenario_3_aws_compromised_vps(self):
        res = self.tracer.trace(SCENARIO_3_AWS_COMPROMISED_VPS)
        origin = res["origin_summary"]
        self.assertEqual(origin["candidate_origin_ip"], "54.214.23.11")
        self.assertEqual(origin["country_code"], "US")
        self.assertIn("Amazon", origin["as_org"])
        self.assertEqual(origin["infrastructure_type"], "Cloud Datacenter / VPS")
        self.assertIn("DATACENTER_IP", origin["threat_tags"])

    def test_scenario_4_legitimate_m365(self):
        res = self.tracer.trace(SCENARIO_4_LEGITIMATE_M365)
        origin = res["origin_summary"]
        self.assertEqual(origin["candidate_origin_ip"], "40.92.18.25")
        self.assertFalse(origin["is_suspicious_infra"])
        self.assertIn("Microsoft", origin["as_org"])


if __name__ == "__main__":
    unittest.main()
