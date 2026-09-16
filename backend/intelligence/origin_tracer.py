"""
Origin-Tracing & Geospatial Intelligence Module (Part 2: Intelligence Engine)

Performs deep forensic tracing of email origin infrastructure:
1. Parses Received: relay headers into chronological order (Submission -> Transit -> Recipient).
2. Filters RFC 1918 / loopback / bogon IP addresses.
3. Identifies the Earliest Observable Untrusted Public Hop (Candidate Origin).
4. Enriches hops with offline MaxMind GeoLite2 City & ASN intelligence.
5. Flags infrastructure threats (Tor exit nodes, bulletproof hosters, cloud datacenters).
6. Computes hop-to-hop travel speed and detects tunneling / header spoofing anomalies.
7. Generates structured data contracts for the Correlation Graph (Part 2) and Leaflet/Mapbox Map (Part 3).
"""

import os
import re
import math
import json
import ipaddress
import email
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any, Tuple

# Try loading geoip2; fall back gracefully if unavailable
try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


# Paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, "data")
CITY_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")
ASN_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb")
THREAT_INFRA_PATH = os.path.join(DATA_DIR, "threat_infra.json")

# Regular expressions for IP and header matching
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")


def is_valid_ip(ip_str: str) -> bool:
    """Check whether a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to RFC 1918, loopback, or reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
            or ip.is_multicast
        )
    except ValueError:
        return True


def get_subnet_24(ip_str: str) -> Optional[str]:
    """Return the /24 CIDR prefix for IPv4 (useful for correlation clustering)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            octets = ip_str.split(".")
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        return str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
    except Exception:
        return None


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance between two points in kilometers."""
    r = 6371.0  # Earth radius in kilometers
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


@dataclass
class HopLocation:
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None


@dataclass
class HopNetwork:
    asn: Optional[int] = None
    as_org: Optional[str] = None
    network: Optional[str] = None
    infra_category: str = "Unknown"  # Residential, Cloud/Datacenter, Tor/Proxy, Bulletproof, Internal
    is_suspicious: bool = False
    threat_tags: List[str] = field(default_factory=list)


@dataclass
class RelayHop:
    hop_index: int
    raw_header: str
    ip: Optional[str]
    from_host: Optional[str]
    by_host: Optional[str]
    protocol: Optional[str]
    auth_mechanism: Optional[str]
    timestamp_raw: Optional[str]
    timestamp_iso: Optional[str]
    is_private: bool
    hop_type: str  # INTERNAL_LAN, CANDIDATE_ORIGIN, TRANSIT_RELAY, RECEIVING_GATEWAY
    location: Optional[HopLocation] = None
    network: Optional[HopNetwork] = None
    speed_from_prev_kmh: Optional[float] = None
    dist_from_prev_km: Optional[float] = None
    anomaly_flags: List[str] = field(default_factory=list)


class ThreatIntelligence:
    """Maintains known threat infrastructure lists."""

    def __init__(self, threat_file: str = THREAT_INFRA_PATH):
        self.known_tor_asns = set()
        self.known_bulletproof_asns = set()
        self.cloud_datacenter_asns = set()
        self.known_tor_exit_ips = set()
        self.load(threat_file)

    def load(self, threat_file: str):
        if os.path.exists(threat_file):
            try:
                with open(threat_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.known_tor_asns = set(data.get("known_tor_asns", []))
                    self.known_bulletproof_asns = set(data.get("known_bulletproof_asns", []))
                    self.cloud_datacenter_asns = set(data.get("cloud_datacenter_asns", []))
                    self.known_tor_exit_ips = set(data.get("known_tor_exit_ips", []))
            except Exception as e:
                print(f"[Warning] Failed loading threat_infra.json: {e}")

    def evaluate(self, ip: Optional[str], asn: Optional[int], as_org: Optional[str]) -> Tuple[str, bool, List[str]]:
        category = "Standard Public Network"
        is_suspicious = False
        tags = []

        if not ip or is_private_ip(ip):
            return "Internal / RFC1918", False, []

        # 1. Tor Exit Node Check
        if ip in self.known_tor_exit_ips or (asn and asn in self.known_tor_asns):
            category = "Tor / Anonymizing Proxy"
            is_suspicious = True
            tags.append("TOR_EXIT_NODE")

        # 2. Bulletproof Hosting Check
        elif asn and asn in self.known_bulletproof_asns:
            category = "Bulletproof / High-Risk Hosting"
            is_suspicious = True
            tags.append("BULLETPROOF_HOSTING")

        # 3. Cloud / Datacenter Hosting Check
        elif asn and asn in self.cloud_datacenter_asns:
            category = "Cloud Datacenter / VPS"
            tags.append("DATACENTER_IP")

        # 4. Keyword heuristic check on Org name
        if as_org:
            org_lower = as_org.lower()
            if any(w in org_lower for w in ["tor", "zwiebel", "anonym", "privacy", "exit"]):
                category = "Tor / Anonymizing Proxy"
                is_suspicious = True
                if "TOR_EXIT_NODE" not in tags:
                    tags.append("ANONYMIZING_PROXY")
            elif any(w in org_lower for w in ["amazon", "aws", "digitalocean", "hetzner", "ovh", "linode", "vultr", "google cloud", "azure"]):
                if category == "Standard Public Network":
                    category = "Cloud Datacenter / VPS"
                    tags.append("DATACENTER_IP")

        return category, is_suspicious, tags


class GeoEnricher:
    """Enriches IP addresses with MaxMind GeoLite2 City & ASN details, with offline fallback."""

    def __init__(self, city_db_path: str = CITY_DB_PATH, asn_db_path: str = ASN_DB_PATH):
        self.city_reader = None
        self.asn_reader = None
        self.threat_intel = ThreatIntelligence()

        if HAS_GEOIP2:
            if os.path.exists(city_db_path):
                try:
                    self.city_reader = geoip2.database.Reader(city_db_path)
                except Exception as e:
                    print(f"[Warning] Failed loading GeoLite2-City: {e}")

            if os.path.exists(asn_db_path):
                try:
                    self.asn_reader = geoip2.database.Reader(asn_db_path)
                except Exception as e:
                    print(f"[Warning] Failed loading GeoLite2-ASN: {e}")

    def close(self):
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()

    def enrich(self, ip_str: Optional[str]) -> Tuple[Optional[HopLocation], Optional[HopNetwork]]:
        if not ip_str or is_private_ip(ip_str):
            loc = HopLocation(
                city="Local Network",
                region="Private Subnet",
                country="Internal",
                country_code="LOCAL",
                lat=None,
                lon=None
            )
            net = HopNetwork(
                asn=None,
                as_org="RFC 1918 Private Range",
                infra_category="Internal / RFC1918",
                is_suspicious=False,
                threat_tags=[]
            )
            return loc, net

        loc = HopLocation()
        net = HopNetwork()

        # 1. City / Coordinates lookup
        if self.city_reader:
            try:
                res = self.city_reader.city(ip_str)
                loc.city = res.city.name
                loc.region = res.subdivisions.most_specific.name if res.subdivisions else None
                loc.country = res.country.name
                loc.country_code = res.country.iso_code
                loc.lat = res.location.latitude
                loc.lon = res.location.longitude
                loc.postal = res.location.postal_code
                loc.timezone = res.location.time_zone
            except Exception:
                pass

        # 2. ASN lookup
        if self.asn_reader:
            try:
                asn_res = self.asn_reader.asn(ip_str)
                net.asn = asn_res.autonomous_system_number
                net.as_org = asn_res.autonomous_system_organization
                net.network = str(asn_res.network) if asn_res.network else None
            except Exception:
                pass

        # 3. Threat Intelligence evaluation
        category, is_suspicious, tags = self.threat_intel.evaluate(ip_str, net.asn, net.as_org)
        net.infra_category = category
        net.is_suspicious = is_suspicious
        net.threat_tags = tags

        return loc, net


class OriginTracer:
    """
    Forensic Origin-Tracing Engine:
    Reconstructs relay path, identifies earliest untrusted hop, and scores anomalies.
    """

    def __init__(self, enricher: Optional[GeoEnricher] = None):
        self.enricher = enricher or GeoEnricher()

    def parse_raw_received_headers(self, headers_text: str) -> List[str]:
        """Extract all 'Received:' header strings from raw header text."""
        # Unfold multiline headers
        unfolded = re.sub(r"\r?\n[ \t]+", " ", headers_text)
        lines = unfolded.splitlines()

        received_headers = []
        for line in lines:
            line_str = line.strip()
            if line_str.lower().startswith("received:"):
                # Remove leading 'Received:' prefix
                clean_hdr = line_str[len("received:"):].strip()
                received_headers.append(clean_hdr)

        # Received headers are prepended: top header is recipient's MTA, bottom is sender.
        # Reverse to get chronological submission order (Hop 1 -> Hop 2 -> Hop N)
        received_headers.reverse()
        return received_headers

    def parse_single_hop(self, hop_index: int, raw_header: str) -> RelayHop:
        """Parse individual Received header tokens into structured RelayHop."""
        from_host = None
        by_host = None
        protocol = None
        auth_mech = None
        extracted_ip = None
        timestamp_raw = None
        timestamp_iso = None

        # Extract timestamp after semicolon
        if ";" in raw_header:
            parts = raw_header.split(";")
            body_part = parts[0]
            timestamp_raw = parts[-1].strip()
            try:
                dt = parsedate_to_datetime(timestamp_raw)
                timestamp_iso = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                timestamp_iso = None
        else:
            body_part = raw_header

        # Extract "from <host>"
        from_match = re.search(r"\bfrom\s+([^\s\(\)]+)", body_part, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1).strip("[]()")

        # Extract "by <host>"
        by_match = re.search(r"\bby\s+([^\s\(\)]+)", body_part, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1).strip("[]()")

        # Extract "with <protocol>"
        with_match = re.search(r"\bwith\s+([a-zA-Z0-9_\-]+)", body_part, re.IGNORECASE)
        if with_match:
            protocol = with_match.group(1).upper()
            if "ESMTPSA" in protocol:
                auth_mech = "SMTP_AUTH"

        # Search for IP addresses in brackets or parens first [x.x.x.x], then unbracketed
        bracket_ip_match = re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-fA-F0-9:]+)\]", body_part)
        if bracket_ip_match and is_valid_ip(bracket_ip_match.group(1)):
            extracted_ip = bracket_ip_match.group(1)
        else:
            # Fallback scan all IPv4 matches
            ips = IPV4_REGEX.findall(body_part)
            for cand in ips:
                if is_valid_ip(cand):
                    extracted_ip = cand
                    break

        is_priv = is_private_ip(extracted_ip) if extracted_ip else True

        return RelayHop(
            hop_index=hop_index,
            raw_header=raw_header,
            ip=extracted_ip,
            from_host=from_host,
            by_host=by_host,
            protocol=protocol,
            auth_mechanism=auth_mech,
            timestamp_raw=timestamp_raw,
            timestamp_iso=timestamp_iso,
            is_private=is_priv,
            hop_type="TRANSIT_RELAY"
        )

    def trace(self, raw_headers: str) -> Dict[str, Any]:
        """
        Execute full origin tracing on raw email headers.
        Returns comprehensive forensic report contract.
        """
        raw_hops = self.parse_raw_received_headers(raw_headers)
        if not raw_hops:
            return {
                "error": "No Received: headers found in email.",
                "relay_hops": [],
                "origin_summary": None,
                "map_features": None
            }

        hops: List[RelayHop] = []
        for idx, raw_h in enumerate(raw_hops, start=1):
            hop = self.parse_single_hop(idx, raw_h)
            # Enrich with GeoLite2 & Threat data
            loc, net = self.enricher.enrich(hop.ip)
            hop.location = loc
            hop.network = net
            hops.append(hop)

        # Identify Candidate Origin (Earliest Observable Untrusted Public Hop)
        candidate_hop: Optional[RelayHop] = None
        for hop in hops:
            if not hop.is_private and hop.ip:
                hop.hop_type = "CANDIDATE_ORIGIN"
                candidate_hop = hop
                break
            else:
                hop.hop_type = "INTERNAL_LAN"

        # Label remaining hops
        if candidate_hop:
            for hop in hops:
                if hop.hop_index > candidate_hop.hop_index:
                    if hop.hop_index == len(hops):
                        hop.hop_type = "RECEIVING_GATEWAY"
                    else:
                        hop.hop_type = "TRANSIT_RELAY"

        # Compute Hop-to-Hop Speed and Anomalies
        flight_path: List[List[float]] = []
        cross_border_hops = 0
        prev_country = None
        prev_hop: Optional[RelayHop] = None
        total_distance_km = 0.0

        for hop in hops:
            if hop.location and hop.location.lat is not None and hop.location.lon is not None:
                flight_path.append([round(hop.location.lat, 4), round(hop.location.lon, 4)])

                # Check cross border
                current_country = hop.location.country_code
                if prev_country and current_country and prev_country != current_country:
                    cross_border_hops += 1
                if current_country:
                    prev_country = current_country

                # Check travel speed against previous hop
                if prev_hop and prev_hop.location and prev_hop.location.lat is not None:
                    dist = haversine_distance(
                        prev_hop.location.lat, prev_hop.location.lon,
                        hop.location.lat, hop.location.lon
                    )
                    hop.dist_from_prev_km = round(dist, 1)
                    total_distance_km += dist

                    # If timestamps exist, calculate speed
                    if hop.timestamp_iso and prev_hop.timestamp_iso:
                        try:
                            t1 = datetime.fromisoformat(prev_hop.timestamp_iso)
                            t2 = datetime.fromisoformat(hop.timestamp_iso)
                            time_diff_sec = abs((t2 - t1).total_seconds())

                            if time_diff_sec > 0:
                                speed_kmh = (dist / time_diff_sec) * 3600.0
                                hop.speed_from_prev_kmh = round(speed_kmh, 1)

                                # Impossible speed (> 1,200 km/h with high distance) -> Flag VPN/tunnel
                                if dist > 500 and speed_kmh > 1500.0 and time_diff_sec < 10:
                                    hop.anomaly_flags.append("IMPOSSIBLE_TRAVEL_SPEED")
                        except Exception:
                            pass

                prev_hop = hop

        # Determine Forensic Confidence & Reasoning
        confidence = "LOW"
        reasoning_points = []

        if candidate_hop:
            reasoning_points.append(
                f"Earliest observable public transit hop identified at {candidate_hop.ip}"
            )
            if candidate_hop.location and candidate_hop.location.country:
                reasoning_points.append(
                    f"Infrastructure geolocated to {candidate_hop.location.city or 'Unknown City'}, {candidate_hop.location.country}"
                )

            if candidate_hop.network and candidate_hop.network.as_org:
                reasoning_points.append(
                    f"Operating under ASN {candidate_hop.network.asn or 'N/A'} ({candidate_hop.network.as_org})"
                )

            if candidate_hop.network and candidate_hop.network.is_suspicious:
                reasoning_points.append(
                    f"High-risk infrastructure flag: {candidate_hop.network.infra_category}"
                )

            # Confidence determination
            if candidate_hop.auth_mechanism == "SMTP_AUTH" or (candidate_hop.protocol and "ESMTPSA" in candidate_hop.protocol):
                confidence = "HIGH"
                reasoning_points.append("Origin submitted via authenticated SMTP session (ESMTPSA).")
            elif candidate_hop.hop_index == 1:
                confidence = "HIGH"
                reasoning_points.append("Direct submission from originating client (Hop 1).")
            elif candidate_hop.hop_index == 2 and hops[0].is_private:
                confidence = "HIGH"
                reasoning_points.append("Border gateway directly forwarding from internal client subnet.")
            else:
                confidence = "MEDIUM"
                reasoning_points.append("Earliest public relay observed; preceding hops traverse external intermediate relays.")
        else:
            reasoning_points.append("No public IP hop observed in relay chain; all headers appear internal or synthesized.")

        # Build Output Structure
        origin_summary = None
        graph_entities = None

        if candidate_hop:
            origin_summary = {
                "candidate_origin_ip": candidate_hop.ip,
                "subnet_24": get_subnet_24(candidate_hop.ip),
                "country": candidate_hop.location.country if candidate_hop.location else None,
                "country_code": candidate_hop.location.country_code if candidate_hop.location else None,
                "city": candidate_hop.location.city if candidate_hop.location else None,
                "region": candidate_hop.location.region if candidate_hop.location else None,
                "coordinates": [candidate_hop.location.lat, candidate_hop.location.lon] if candidate_hop.location and candidate_hop.location.lat is not None else None,
                "timezone": candidate_hop.location.timezone if candidate_hop.location else None,
                "asn": f"AS{candidate_hop.network.asn}" if candidate_hop.network and candidate_hop.network.asn else None,
                "asn_number": candidate_hop.network.asn if candidate_hop.network else None,
                "as_org": candidate_hop.network.as_org if candidate_hop.network else None,
                "infrastructure_type": candidate_hop.network.infra_category if candidate_hop.network else "Unknown",
                "is_suspicious_infra": candidate_hop.network.is_suspicious if candidate_hop.network else False,
                "threat_tags": candidate_hop.network.threat_tags if candidate_hop.network else [],
                "confidence": confidence,
                "forensic_reasoning": " ".join(reasoning_points)
            }

            graph_entities = {
                "ip_node": candidate_hop.ip,
                "subnet_node": get_subnet_24(candidate_hop.ip),
                "asn_node": f"AS{candidate_hop.network.asn}" if candidate_hop.network and candidate_hop.network.asn else None,
                "as_org": candidate_hop.network.as_org if candidate_hop.network else None,
                "country_code": candidate_hop.location.country_code if candidate_hop.location else None
            }

        map_features = {
            "flight_path": flight_path,
            "total_distance_km": round(total_distance_km, 1),
            "hop_count": len(hops),
            "cross_border_hops": cross_border_hops,
            "has_speed_anomalies": any(bool(h.anomaly_flags) for h in hops)
        }

        # TraceMap.jsx direct compatibility payload
        origin_compat = None
        if origin_summary:
            coords = origin_summary.get("coordinates") or [0.0, 0.0]
            origin_compat = {
                "ip": origin_summary.get("candidate_origin_ip") or "127.0.0.1",
                "country": origin_summary.get("country") or "Unknown",
                "city": origin_summary.get("city") or "Unknown",
                "lat": coords[0],
                "lng": coords[1],
                "is_vpn_tor": bool(origin_summary.get("is_suspicious_infra")),
                "isp": origin_summary.get("as_org") or "Unknown ISP",
                "asn": origin_summary.get("asn") or "N/A"
            }

        return {
            "origin": origin_compat,
            "origin_summary": origin_summary,
            "relay_hops": [asdict(h) for h in hops],
            "map_features": map_features,
            "graph_entities": graph_entities
        }


# Convenience standalone runner for CLI and testing
if __name__ == "__main__":
    import sys

    sample_header = """Received: from mail-relay.target.com (192.168.1.10) by mx.google.com with ESMTP id abc123; Tue, 08 Sep 2026 14:15:20 +0000
Received: from tor-exit-node.net (185.220.101.5) by mail-relay.target.com with ESMTP id hop2; Tue, 08 Sep 2026 14:15:18 +0000
Received: from internal-client (10.0.0.15) by tor-exit-node.net with ESMTPSA id hop1; Tue, 08 Sep 2026 14:15:10 +0000"""

    tracer = OriginTracer()
    res = tracer.trace(sample_header)
    print(json.dumps(res, indent=2))
