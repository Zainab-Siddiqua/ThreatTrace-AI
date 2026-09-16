"""
Curated Realistic Email Header Scenarios for Hackathon Demo & Validation.
Covers:
1. Bulgarian Bulletproof Relay (PayPal credential harvester)
2. Tor-Anonymized Urgent CEO Fraud (Wire Transfer)
3. Compromised Cloud VPS Phishing (AWS EC2)
4. Legitimate Microsoft 365 Corporate Control Email
"""

SCENARIO_1_BULLETPROOF_RELAY = """Received: from mail-relay.nl-forward.net (185.220.101.6) by mx.google.com with ESMTPS id abc789
  for <victim@corporation.com>; Tue, 08 Sep 2026 14:20:15 +0000
Received: from offshore-node.sofia-cloud.bg (91.215.85.17) by mail-relay.nl-forward.net with ESMTP id hop2
  for <victim@corporation.com>; Tue, 08 Sep 2026 14:20:10 +0000
Received: from workstation-win10 (192.168.10.55) by offshore-node.sofia-cloud.bg with ESMTPSA id hop1
  for <victim@corporation.com>; Tue, 08 Sep 2026 14:20:02 +0000
From: "PayPal Support" <service@paypa1-security-update.com>
To: victim@corporation.com
Subject: [URGENT] Your PayPal Account Has Been Restricted
Date: Tue, 08 Sep 2026 14:20:00 +0000
"""

SCENARIO_2_TOR_CEO_FRAUD = """Received: from protection.outlook.com (40.107.100.45) by mail.acmecorp.com with ESMTPS id m365-rec
  for <cfo@acmecorp.com>; Tue, 08 Sep 2026 09:12:35 +0000
Received: from compromised-relay.hosting.ru (194.67.210.12) by protection.outlook.com with ESMTP id m365-in
  for <cfo@acmecorp.com>; Tue, 08 Sep 2026 09:12:28 +0000
Received: from tor-relay-de.exitnode.org (185.220.101.5) by compromised-relay.hosting.ru with ESMTPSA id relay01
  for <cfo@acmecorp.com>; Tue, 08 Sep 2026 09:12:20 +0000
From: "Robert Vance (CEO)" <ceo@acmecorp-executives.com>
To: cfo@acmecorp.com
Subject: Immediate Wire Transfer Needed for Q3 Acquisition
Date: Tue, 08 Sep 2026 09:12:00 +0000
"""

SCENARIO_3_AWS_COMPROMISED_VPS = """Received: from mx.google.com (209.85.222.180) by inbound.company.org with ESMTPS id g-mx-01
  for <employee@company.org>; Tue, 08 Sep 2026 11:45:10 +0000
Received: from ec2-54-214-23-11.us-west-2.compute.amazonaws.com (54.214.23.11) by mx.google.com with ESMTP id aws-hop
  for <employee@company.org>; Tue, 08 Sep 2026 11:45:04 +0000
Received: from internal-vpn (10.240.0.8) by ec2-54-214-23-11.us-west-2.compute.amazonaws.com with ESMTPSA id sub01
  for <employee@company.org>; Tue, 08 Sep 2026 11:44:55 +0000
From: "IT Helpdesk" <helpdesk@corporate-sso-login.net>
To: employee@company.org
Subject: Action Required: Mandatory SSO Certificate Renewal
Date: Tue, 08 Sep 2026 11:44:50 +0000
"""

SCENARIO_4_LEGITIMATE_M365 = """Received: from mx1.google.com (142.250.102.27) by receiver.org with ESMTPS id legit-hop3
  for <client@receiver.org>; Tue, 08 Sep 2026 16:30:15 +0000
Received: from mail-eur01-oln.protection.outlook.com (40.107.94.120) by mx1.google.com with ESMTPS id legit-hop2
  for <client@receiver.org>; Tue, 08 Sep 2026 16:30:10 +0000
Received: from out-relay.outlook.office365.com (40.92.18.25) by mail-eur01-oln.protection.outlook.com with ESMTPS id legit-hop1
  for <client@receiver.org>; Tue, 08 Sep 2026 16:30:05 +0000
From: "Alice Smith" <alice@trusted-partner.com>
To: client@receiver.org
Subject: Meeting Agenda for Thursday's Partnership Review
Date: Tue, 08 Sep 2026 16:30:00 +0000
"""

DEMO_SCENARIOS = {
    "BULLETPROOF_RELAY_PHISH": SCENARIO_1_BULLETPROOF_RELAY,
    "TOR_CEO_FRAUD": SCENARIO_2_TOR_CEO_FRAUD,
    "AWS_COMPROMISED_VPS": SCENARIO_3_AWS_COMPROMISED_VPS,
    "LEGITIMATE_M365": SCENARIO_4_LEGITIMATE_M365
}
