import networkx as nx
from typing import List, Dict, Any, Optional, Tuple, Union

class ThreatGraphEngine:
    """
    ThreatGraphEngine: SIH Section 7 Graph-based Multi-Signal Attribution Engine.
    Handles Evidence Normalization, Infrastructure Relationship Scoring (Section 7D),
    and Multi-Signal Campaign Syndicate Clustering (Section 7E).
    """

    def __init__(self):
        # Undirected graph storing senders, domains, IPs, and correlation links
        self.graph = nx.Graph()
        # Catalog of normalized forensic artifacts keyed by email_id
        self.artifacts: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _extract_val(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @classmethod
    def calculate_relationship_score(
        cls,
        artifact_1: Any,
        artifact_2: Any,
        return_details: bool = False
    ) -> Union[int, Tuple[int, List[str]]]:
        """
        Section 7D: Infrastructure Relationship Scoring Formula.
        Calculates infrastructure similarity score between two email forensic artifacts:
        - Same origin IP: +50 points
        - Same domain: +30 points
        - Shared suspicious URL / payload link: +20 points
        - Authentication failure overlap (both SPF/DMARC fail): +15 points
        - High risk domain age (< 30 days old): +10 points
        """
        score = 0
        reasons: List[str] = []

        # 1. Same origin IP: +50 points
        ip1 = cls._extract_val(artifact_1, "origin_ip")
        ip2 = cls._extract_val(artifact_2, "origin_ip")
        if ip1 and ip2 and str(ip1).strip() == str(ip2).strip():
            score += 50
            reasons.append("Shared IP")

        # 2. Same domain: +30 points
        dom1 = cls._extract_val(artifact_1, "domain")
        dom2 = cls._extract_val(artifact_2, "domain")
        if dom1 and dom2 and str(dom1).strip().lower() == str(dom2).strip().lower():
            score += 30
            reasons.append("Shared Domain")

        # 3. Shared suspicious URL / payload link: +20 points
        urls1 = cls._extract_val(artifact_1, "urls") or []
        urls2 = cls._extract_val(artifact_2, "urls") or []
        set_urls1 = {str(u).strip() for u in urls1 if u}
        set_urls2 = {str(u).strip() for u in urls2 if u}
        if set_urls1 and set_urls2 and (set_urls1 & set_urls2):
            score += 20
            reasons.append("Shared URL/Payload")

        # 4. Authentication failure overlap (both SPF/DMARC fail): +15 points
        spf1 = str(cls._extract_val(artifact_1, "spf_status", "") or "").upper()
        dmarc1 = str(cls._extract_val(artifact_1, "dmarc_status", "") or "").upper()
        spf2 = str(cls._extract_val(artifact_2, "spf_status", "") or "").upper()
        dmarc2 = str(cls._extract_val(artifact_2, "dmarc_status", "") or "").upper()

        auth1_fails = (spf1 == "FAIL" or dmarc1 == "FAIL")
        auth2_fails = (spf2 == "FAIL" or dmarc2 == "FAIL")
        if auth1_fails and auth2_fails:
            score += 15
            reasons.append("Shared Auth Anomaly")

        # 5. High risk domain age (< 30 days old): +10 points
        age1 = cls._extract_val(artifact_1, "domain_age_days")
        age2 = cls._extract_val(artifact_2, "domain_age_days")
        is_young_1 = age1 is not None and isinstance(age1, (int, float)) and 0 <= age1 < 30
        is_young_2 = age2 is not None and isinstance(age2, (int, float)) and 0 <= age2 < 30
        if is_young_1 or is_young_2:
            score += 10
            reasons.append("High-Risk Domain Age")

        if return_details:
            return score, reasons
        return score

    @classmethod
    def calculate_relationship_details(cls, artifact_1: Any, artifact_2: Any) -> Dict[str, Any]:
        """
        Convenience wrapper returning structured scoring details.
        """
        score, reasons = cls.calculate_relationship_score(artifact_1, artifact_2, return_details=True)
        reason_str = " + ".join(reasons) if reasons else "No Shared Signals"
        return {
            "score": score,
            "reasons": reasons,
            "is_syndicate": score >= 60,
            "summary": f"CORRELATION_SCORE: {score} ({reason_str})" if reasons else f"CORRELATION_SCORE: {score}"
        }

    def ingest_artifact(self, artifact: Any):
        """
        Section 7 Evidence Normalization ingestion.
        Normalizes forensic context from Part 1 / Geospatial tracer, adds entity nodes,
        and constructs multi-signal correlation edges when relationship score >= 60.
        """
        email_id = str(self._extract_val(artifact, "email_id", f"MSG-{len(self.artifacts) + 1}"))
        sender = str(self._extract_val(artifact, "sender", "unknown@domain.com"))
        domain = str(self._extract_val(artifact, "domain", "domain.com"))
        origin_ip = str(self._extract_val(artifact, "origin_ip", "0.0.0.0"))
        location = self._extract_val(artifact, "location") or {}
        spf_status = str(self._extract_val(artifact, "spf_status", "FAIL")).upper()
        dkim_status = str(self._extract_val(artifact, "dkim_status", "FAIL")).upper()
        dmarc_status = str(self._extract_val(artifact, "dmarc_status", "FAIL")).upper()
        domain_age_days = self._extract_val(artifact, "domain_age_days")
        urls = self._extract_val(artifact, "urls") or []
        fraud_score = float(self._extract_val(artifact, "fraud_score", self._extract_val(artifact, "threat_score", 0.85) or 0.85))

        normalized = {
            "email_id": email_id,
            "sender": sender,
            "domain": domain,
            "origin_ip": origin_ip,
            "location": location,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "domain_age_days": domain_age_days,
            "urls": urls,
            "fraud_score": fraud_score
        }
        self.artifacts[email_id] = normalized

        # Add Nodes with styling attributes for the frontend
        self.graph.add_node(
            sender,
            type="sender",
            label=sender,
            color="#ff7675",
            email_id=email_id,
            fraud_score=fraud_score,
            location=location
        )
        self.graph.add_node(
            domain,
            type="domain",
            label=domain,
            color="#74b9ff",
            domain_age_days=domain_age_days
        )
        self.graph.add_node(
            origin_ip,
            type="ip",
            label=origin_ip,
            color="#a29bfe",
            location=location
        )

        # Add Base Edges linking the infrastructure
        self.graph.add_edge(
            sender,
            domain,
            relation="SENT_FROM_DOMAIN",
            title=f"SENT_FROM_DOMAIN\nSender: {sender}\nDomain: {domain}\nEmail ID: {email_id}",
            email_id=email_id,
            edge_type="infrastructure"
        )
        self.graph.add_edge(
            domain,
            origin_ip,
            relation="HOSTED_ON_IP",
            title=f"HOSTED_ON_IP\nDomain: {domain}\nIP: {origin_ip}\nEmail ID: {email_id}",
            email_id=email_id,
            edge_type="infrastructure"
        )

        # Compute multi-signal correlation edges (Score >= 60)
        self._recompute_correlation_edges()

    def ingest_email_event(self, sender: str, ip: str, domain: str, email_id: str, threat_score: float = 0.0, **kwargs):
        """
        Backward-compatible helper for ingesting email events with positional/named args.
        """
        artifact = {
            "email_id": email_id,
            "sender": sender,
            "origin_ip": ip,
            "domain": domain,
            "fraud_score": threat_score,
            **kwargs
        }
        self.ingest_artifact(artifact)

    def _recompute_correlation_edges(self):
        """
        Evaluates pairs of ingested artifacts and forms correlation edges between
        sender personas/entities when relationship score >= 60.
        """
        # Remove existing correlation edges to prevent stale links
        existing_corr = [
            (u, v) for u, v, d in self.graph.edges(data=True)
            if d.get("edge_type") == "correlation"
        ]
        for u, v in existing_corr:
            self.graph.remove_edge(u, v)

        artifact_list = list(self.artifacts.values())
        n = len(artifact_list)

        for i in range(n):
            for j in range(i + 1, n):
                a1 = artifact_list[i]
                a2 = artifact_list[j]
                score, reasons = self.calculate_relationship_score(a1, a2, return_details=True)

                if score >= 60:
                    # Determine endpoints for the correlation link
                    u = a1["sender"]
                    v = a2["sender"]
                    if u == v:
                        u = a1["domain"]
                        v = a2["domain"]
                    if u == v:
                        continue  # Identical entities

                    reason_str = " & ".join(reasons) if reasons else "Multi-Signal Overlap"
                    rel_label = f"CORRELATION_SCORE: {score} ({reason_str})"
                    title_tooltip = f"Correlation Score: {score} | {reason_str}"

                    self.graph.add_edge(
                        u,
                        v,
                        relation=rel_label,
                        title=title_tooltip,
                        correlation_score=score,
                        reasons=reasons,
                        edge_type="correlation"
                    )

    def analyze_campaigns(self) -> Dict[str, Any]:
        """
        Section 7E: Multi-Signal Campaign Clustering Logic.
        Forms campaign syndicate clusters when relationship score >= 60,
        returns weighted correlation score on edges, and computes Campaign Threat Levels.
        """
        # Build artifact correlation graph where edges indicate score >= 60
        corr_graph = nx.Graph()
        for eid in self.artifacts:
            corr_graph.add_node(eid)

        artifact_list = list(self.artifacts.values())
        n = len(artifact_list)
        for i in range(n):
            for j in range(i + 1, n):
                a1 = artifact_list[i]
                a2 = artifact_list[j]
                score, reasons = self.calculate_relationship_score(a1, a2, return_details=True)
                if score >= 60:
                    corr_graph.add_edge(
                        a1["email_id"],
                        a2["email_id"],
                        score=score,
                        reasons=reasons
                    )

        campaigns = []
        clusters = list(nx.connected_components(corr_graph))

        for idx, cluster in enumerate(clusters):
            eids = list(cluster)
            cluster_artifacts = [self.artifacts[eid] for eid in eids if eid in self.artifacts]

            senders = sorted(list({a["sender"] for a in cluster_artifacts}))
            domains = sorted(list({a["domain"] for a in cluster_artifacts}))
            ips = sorted(list({a["origin_ip"] for a in cluster_artifacts}))
            urls = sorted(list({u for a in cluster_artifacts for u in a.get("urls", []) if u}))

            all_entity_nodes = set(senders) | set(domains) | set(ips)
            is_syndicate = len(cluster_artifacts) > 1 or len(senders) > 1

            fraud_scores = [a.get("fraud_score", 0.0) for a in cluster_artifacts]
            avg_fraud = round(sum(fraud_scores) / len(fraud_scores), 3) if fraud_scores else 0.0
            max_fraud = round(max(fraud_scores), 3) if fraud_scores else 0.0

            # Compute Campaign Threat Level (CRITICAL, HIGH, ELEVATED)
            if (is_syndicate and (avg_fraud >= 0.80 or max_fraud >= 0.85)) or (len(all_entity_nodes) >= 5 and avg_fraud >= 0.75) or max_fraud >= 0.95:
                threat_level = "CRITICAL"
            elif is_syndicate or avg_fraud >= 0.75 or (len(all_entity_nodes) >= 4 and avg_fraud >= 0.50):
                threat_level = "HIGH"
            else:
                threat_level = "ELEVATED"

            # Compute max correlation score and aggregated reasons for this syndicate
            cluster_scores = []
            cluster_reasons = set()
            for u_eid, v_eid, data in corr_graph.edges(eids, data=True):
                if u_eid in cluster and v_eid in cluster:
                    cluster_scores.append(data.get("score", 0))
                    for r in data.get("reasons", []):
                        cluster_reasons.add(r)

            max_score = max(cluster_scores) if cluster_scores else (int(avg_fraud * 100))
            reasons_summary = " + ".join(sorted(cluster_reasons)) if cluster_reasons else "Infrastructure Co-location"

            campaigns.append({
                "campaign_id": f"CAMP-{1000 + idx}",
                "is_coordinated_gang": is_syndicate,
                "threat_level": threat_level,
                "node_count": len(all_entity_nodes),
                "senders": senders,
                "domains": domains,
                "infrastructure_ips": ips,
                "urls": urls,
                "email_ids": eids,
                "fraud_metrics": {
                    "avg_fraud_score": avg_fraud,
                    "max_fraud_score": max_fraud
                },
                "correlation_score": max_score,
                "correlation_reasons": sorted(list(cluster_reasons)),
                "correlation_summary": f"CORRELATION_SCORE: {max_score} ({reasons_summary})" if is_syndicate else "Isolated Attack Node"
            })

        return {
            "summary": {
                "total_entities": self.graph.number_of_nodes(),
                "total_relationships": self.graph.number_of_edges(),
                "identified_campaigns": len(campaigns),
                "critical_threats": sum(1 for c in campaigns if c.get("threat_level") == "CRITICAL"),
                "active_syndicates": sum(1 for c in campaigns if c.get("is_coordinated_gang"))
            },
            "campaigns": campaigns,
            "vis_graph": self.get_ui_graph_payload()
        }

    def get_ui_graph_payload(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Formats graph nodes and edges into JSON ready for vis-network / react-force-graph.
        Includes hover tooltips, edge weights, and forensic telemetry.
        """
        nodes = []
        for node, data in self.graph.nodes(data=True):
            nodes.append({
                "id": node,
                "label": data.get("label", node),
                "type": data.get("type", "unknown"),
                "color": data.get("color", "#95a5a6"),
                "location": data.get("location"),
                "fraud_score": data.get("fraud_score"),
                "domain_age_days": data.get("domain_age_days")
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "relation": data.get("relation", "CONNECTED_TO"),
                "title": data.get("title", data.get("relation", "CONNECTED_TO")),
                "score": data.get("correlation_score"),
                "reasons": data.get("reasons", []),
                "edge_type": data.get("edge_type", "infrastructure")
            })

        return {"nodes": nodes, "edges": edges}

# Singleton instance ready for API import
threat_engine = ThreatGraphEngine()