# Microsoft Sentinel SIEM Lab: Detecting & Responding to Live Brute Force Attacks

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-Cloud-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Query_Language-742774?style=for-the-badge)

## Summary

I built a Microsoft Sentinel lab in Azure to collect Linux authentication logs and investigate SSH password-guessing activity against an internet-facing Ubuntu VM. I used KQL to examine failed authentication events, configured a scheduled analytics rule with entity mapping, investigated an incident, and configured an NSG deny rule for selected source addresses.

***Revised***: October 20, 2026

---

## Tools Used

- **Microsoft Sentinel** – SIEM for log analysis and incident management
- **Microsoft Defender XDR** – Unified security portal
- **Log Analytics Workspace** – Log storage and query engine
- **KQL (Kusto Query Language)** – Detection and threat hunting queries
- **Azure Virtual Machine** – Ubuntu honeypot
- **Network Security Groups** – Firewall rules for remediation

---

## Lab Architecture

```
                    ┌─────────────────┐
                    │    INTERNET     │
                    │    Attackers    │
                    │  (Brute Force)  │
                    └────────┬────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                         AZURE CLOUD                              │
│                                                                  │
│   ┌─────────────────┐         ┌─────────────────────────────┐    │
│   │  Ubuntu VM      │         │   Log Analytics Workspace   │    │
│   │  (Honeypot)     │────────▶│                             │    │
│   │                 │ Syslog  │   ┌─────────────────────┐   │    │
│   │ • SSH Exposed   │  via    │   │ Microsoft Sentinel  │   │    │
│   │ • Firewall Off  │  AMA    │   │ • Analytics Rules   │   │    │
│   │ • Port 22 Open  │         │   │ • Incidents         │   │    │
│   └─────────────────┘         │   │ • Workbooks         │   │    │
│                               │   │ • Entity Mapping    │   │    │
│                               │   └─────────────────────┘   │    │
│                               └─────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Setting Up the Environment

### Created the Azure Infrastructure

Started by creating a Resource Group to organize all lab resources in one place. This makes it easy to manage and delete everything when the lab is complete.

![Resource Group](screenshots/resource-group.png)

Next, created a Log Analytics Workspace. This is where all the security logs get stored and where Sentinel runs its queries.

![Log Analytics Workspace](screenshots/log-analytics-workspace.png)

### Deployed Microsoft Sentinel

Added Microsoft Sentinel to the Log Analytics Workspace. Sentinel is the SIEM that analyzes logs, generates alerts, and manages incidents.

![Sentinel Enabled](screenshots/sentinel-enabled.png)

---

## Configuring Data Ingestion

### Installed the Syslog Solution

From the Content Hub, installed the Syslog solution to enable Linux log collection. This provides the data connector needed to pull authentication logs from the honeypot VM.

![Content Hub](screenshots/content-hub.png)

### Created a Data Collection Rule

Configured a Data Collection Rule (DCR) to specify which logs to collect and where to send them. Set it to collect LOG_AUTH events, which capture all authentication activity including failed SSH logins.

![Data Collection Rule](screenshots/data-collection-rule.png)

### Connected Azure Activity Logs

Also connected Azure Activity to monitor any changes made in the Azure environment itself.

![Data Connectors](screenshots/data-connectors.png)

---

## Deploying the Honeypot

### Created an Ubuntu VM

Deployed an Ubuntu Server VM with SSH exposed to the internet. This serves as the honeypot to attract real attackers.

![VM Created](screenshots/vm-created.png)

### Opened the Firewall

Configured the Network Security Group to allow ALL inbound traffic. This makes the VM discoverable by attackers scanning the internet.

![NSG Allow All](screenshots/nsg-allow-all.png)

### Disabled Host Firewall

Connected to the VM via SSH and disabled the host firewall to ensure nothing blocks incoming connection attempts.

```bash
sudo ufw disable
```
![Disabled ufw](screenshots/disabled-ufw.png)

Within hours, attackers found the exposed VM and started brute force attempts.

---

## Building the Detection Rule

### Created a Scheduled Analytics Rule & Configured Entity Mapping

I created a scheduled analytics rule that selects groups with at least five failed SSH authentication events for the same source IP, attempted username, and host within the rule's configured query lookback.

Because the query groups by all three fields, attempts spread across different usernames are counted separately. The threshold is a lab configuration choice, not proof by itself that the activity is malicious.

I mapped the extracted source IP and attempted username to Sentinel entities so they could appear in the incident investigation. These entities help organize the evidence; the original log records remain important for validating the findings.

- **IP Entity** → `Attacker_IP`
- **Account Entity** → `TargetUsername`

**KQL Detection Query:**
```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password"
| extend Attacker_IP = extract(@"from\s([0-9\.]+)", 1, SyslogMessage)
| extend TargetUsername = extract(@"for\s(?:invalid user\s)?(\S+)", 1, SyslogMessage)
| summarize FailedAttempts = count() by Attacker_IP, TargetUsername, HostName
| where FailedAttempts >= 5
```
![Analytics Rule](screenshots/analytics-rule.png)

---

## Attack Results

I queried failed SSH authentication events over a 24-hour lookback and grouped the results by source IP and attempted username.

| Source IP | Attempted Username | Failed Authentication Events |
|-----------|--------------------|------------------------------|
| 152.42.143.239 | root | 21 |
| 159.223.225.34 | root | 18 |
| 159.223.225.34 | postgres | 18 |
| 159.223.225.34 | mysql | 18 |

These are selected rows visible in the query screenshot. The query displays up to 15 groups; this table is not an overall event total.

**Targeted usernames:** `root`, `postgres`, `mysql`, `ubuntu`, `test`, `user`

The observed attempts targeted common usernames such as `postgres`, `mysql`, `root`, and `ubuntu`. The repeated failures are consistent with automated SSH password guessing. The usernames alone do not establish that those accounts existed on the VM or that previously compromised credentials were used.

![KQL Results](screenshots/kql-results.png)

---

## Investigating the Incident

When alerts triggered, Sentinel grouped them into an incident. The investigation graph showed:

- **2 source IPs**: `159.223.225.34` and `152.42.143.239`
- **7 username entities** associated with the incident
- **16 alerts** shown in the incident

![Incidents](screenshots/incidents.png)

![Investigation Graph](screenshots/investigation-graph.png)

## Responding to the Threat

### Documented Findings

I documented the observed password-guessing activity, the source IPs associated with the incident, and the attempted usernames. I assessed the activity as suspicious and selected an NSG deny rule as the manual response.

### Configured an NSG Deny Rule

I configured the `Block_Attackers` deny rule for selected source addresses. Its priority of 190 places it ahead of the existing `DANGER_AllowAll` rule at priority 200.

This demonstrates why rule order matters: the more specific deny rule must be evaluated before the broad allow rule.

![NSG Block Rule](screenshots/nsg-block-rule.png)

### Closed the Incident

I used the incident management workflow to document the assessment and response. The closure screenshot shows the selected status of **Resolved**, classification of **True positive**, and an investigation note describing the NSG action.

![Incident Closed](screenshots/incident-closed.png)

---

## Lab Teardown

After completing the exercise, I deleted the Azure resources used for this lab. The screenshots document the environment at the time of the exercise; it is no longer running.

## What I Learned

**Collection determines visibility.** The data collection rule controls which events reach the workspace. A detection query depends on those events being collected.

**Grouping changes detection behavior.** My query counts failures separately for each source IP, attempted username, and host. Attempts distributed across usernames may not reach the threshold in any one group.

**Entity mapping supports investigation.** Mapping source IPs and attempted usernames makes related entities easier to examine in an incident. An attempted username does not prove that the account exists.

**Events and alerts are different.** Failed authentication records, grouped query results, and incident alerts represent different units and should not be counted interchangeably.

**Firewall priority matters.** The NSG deny rule had priority 190, ahead of the broad allow rule at 200. Reviewing rule order is part of checking the response configuration.

**Documentation should connect actions to evidence.** Queries, incident views, and configuration screenshots each support different parts of the investigation.

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force | T1110 |

